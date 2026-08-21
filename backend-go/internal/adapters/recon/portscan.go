package recon

import (
	"context"
	"encoding/xml"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// Scanner: скан открытых TCP-портов через nmap (порт app/farm/portscan.py).
// Парсер XML — чистая функция (покрыт тестами); запуск подменяется PortScanner.

// PortScanner — {ip: [open_port,...]} (сид для тестов без бинаря).
type PortScanner func(ctx context.Context, ips []string) (map[string][]int, string)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []nmapAddr `xml:"address"`
	Ports     []nmapPort `xml:"ports>port"`
}
type nmapAddr struct {
	AddrType string `xml:"addrtype,attr"`
	Addr     string `xml:"addr,attr"`
}
type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}
type nmapState struct {
	State string `xml:"state,attr"`
}

// nmapService — блок <service> из nmap -sV: имя сервиса + продукт/версия.
type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// ParseNmapXML — {ip: [открытый tcp-порт,...]} из nmap -oX (порт parse_nmap_xml).
func ParseNmapXML(xmlStr string) map[string][]int {
	var run nmapRun
	if err := xml.Unmarshal([]byte(xmlStr), &run); err != nil {
		return map[string][]int{}
	}
	out := map[string][]int{}
	for _, host := range run.Hosts {
		var ip string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		set := map[int]bool{}
		for _, p := range host.Ports {
			if p.Protocol != "tcp" || p.State.State != "open" {
				continue
			}
			n, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			set[n] = true
		}
		if len(set) == 0 {
			continue
		}
		ports := make([]int, 0, len(set))
		for n := range set {
			ports = append(ports, n)
		}
		sort.Ints(ports)
		out[ip] = append(out[ip], ports...)
	}
	return out
}

// ─────────────────────────── прогрессивный скан с сервисами (farm_run) ───────────────────────────
// Полный прогон фермы не бьёт `-p-` по всему сразу: он идёт фазами (быстрый top-100
// → top-1000 → опционально весь диапазон), КАЖДАЯ с -sV, чтобы сервис не остался
// «unknown» (пользователь хочет видеть 9100/tcp и т.п. опознанными). Оркестрацию
// фаз (шаги прогресса, отмена, объединение по хостам) держит app/recon; здесь —
// одна фаза над одним хостом и парсер сервисов.

// NmapPort — открытый порт с сервисом/версией из nmap -sV.
type NmapPort struct {
	Port    int
	Proto   string
	State   string
	Service string // имя сервиса (name), напр. "jetdirect", "http"
	Version string // product + version, напр. "nginx 1.18.0"
}

// NmapPhase — одна фаза прогрессивного скана: имя (для логов) и флаги nmap
// (без -oX/цели — их дописывает раннер).
type NmapPhase struct {
	Name string
	Args []string
}

// NmapPhases — прогрессивный план фаз farm-скана. Фаза 1 (быстрый первый результат)
// — top-100 с лёгким -sV; фаза 2 — top-1000 с -sV; deep=true (port_scan_scope=="all")
// добавляет финальную -p- фазу. Все фазы несут -sV — сервисы обязаны опознаваться.
func NmapPhases(deep bool) []NmapPhase {
	phases := []NmapPhase{
		{Name: "fast", Args: []string{"-Pn", "-T4", "-F", "--open", "-sV", "--version-light"}},
		{Name: "top1000", Args: []string{"-Pn", "-T4", "--top-ports", "1000", "--open", "-sV"}},
	}
	if deep {
		phases = append(phases, NmapPhase{Name: "full", Args: []string{"-Pn", "-T4", "-p-", "--open", "-sV"}})
	}
	return phases
}

// NmapCommand — строка команды одной фазы над хостом (для RunStep.Args во фронте).
func NmapCommand(bin string, phase NmapPhase, host string) string {
	if bin == "" {
		bin = "nmap"
	}
	parts := append([]string{bin}, phase.Args...)
	parts = append(parts, host)
	return strings.Join(parts, " ")
}

// NmapServiceScanner — сид для тестов: одна nmap-фаза над хостом → порты с сервисами.
type NmapServiceScanner func(ctx context.Context, host string, phase NmapPhase) ([]NmapPort, string)

// ParseNmapServicePorts — открытые tcp-порты С сервисом/версией из nmap -sV -oX.
// Плоский список по всему документу (раннер зовёт по одному хосту за раз), сорт по
// номеру порта. Version = product + version (тримленное), если nmap их дал.
func ParseNmapServicePorts(xmlStr string) []NmapPort {
	var run nmapRun
	if err := xml.Unmarshal([]byte(xmlStr), &run); err != nil {
		return nil
	}
	seen := map[int]bool{}
	out := []NmapPort{}
	for _, host := range run.Hosts {
		for _, p := range host.Ports {
			if p.Protocol != "tcp" || p.State.State != "open" {
				continue
			}
			n, err := strconv.Atoi(p.PortID)
			if err != nil || seen[n] {
				continue
			}
			seen[n] = true
			version := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			out = append(out, NmapPort{
				Port: n, Proto: "tcp", State: "open",
				Service: strings.TrimSpace(p.Service.Name), Version: version,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// DefaultNmapServiceScanner — запуск одной nmap-фазы над хостом с -oX и парсингом
// сервисов (порт farm-скана с -sV). Нет бинаря/пустой хост → пусто, без ошибки.
func DefaultNmapServiceScanner(s Settings) NmapServiceScanner {
	return func(ctx context.Context, host string, phase NmapPhase) ([]NmapPort, string) {
		if host == "" || !lookPathOK(s.PortscanNmapBin) {
			return nil, ""
		}
		c, cancel := context.WithTimeout(ctx, s.PortscanTimeout)
		defer cancel()
		args := append(append([]string{}, phase.Args...), "-n", "-oX", "-", host)
		cmd := exec.CommandContext(c, s.PortscanNmapBin, args...)
		out, err := cmd.Output()
		if err != nil {
			return nil, "nmap: " + errName(err)
		}
		return ParseNmapServicePorts(string(out)), ""
	}
}

// DefaultNmapScanner — nmap по списку IP одной командой (порт _run_nmap).
func DefaultNmapScanner(s Settings) PortScanner {
	return func(ctx context.Context, ips []string) (map[string][]int, string) {
		if len(ips) == 0 || !lookPathOK(s.PortscanNmapBin) {
			return map[string][]int{}, ""
		}
		c, cancel := context.WithTimeout(ctx, s.PortscanTimeout)
		defer cancel()
		args := []string{"-Pn", "-n", "-T4", "--open", "-oX", "-"}
		if s.PortscanTopPorts > 0 {
			args = append(args, "--top-ports", strconv.Itoa(s.PortscanTopPorts))
		} else {
			args = append(args, "-p-")
		}
		args = append(args, ips...)
		cmd := exec.CommandContext(c, s.PortscanNmapBin, args...)
		out, err := cmd.Output()
		if err != nil {
			return map[string][]int{}, "nmap: " + errName(err)
		}
		return ParseNmapXML(string(out)), ""
	}
}
