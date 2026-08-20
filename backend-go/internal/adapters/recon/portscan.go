package recon

import (
	"context"
	"encoding/xml"
	"os/exec"
	"sort"
	"strconv"
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
	Protocol string    `xml:"protocol,attr"`
	PortID   string    `xml:"portid,attr"`
	State    nmapState `xml:"state"`
}
type nmapState struct {
	State string `xml:"state,attr"`
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
