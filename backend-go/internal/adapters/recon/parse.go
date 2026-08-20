// Package recon — адаптеры рекон-фермы: чистый разбор целей, DNS-резолв,
// HTTP-пробив, детект технологий и скан JS. БД/модели не импортируются.
// Порт app/farm/core.py (фазы parse и probe): только чистые функции и сеть.
package recon

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// HTTPSPorts — порты, пробиваемые по HTTPS (у остальных по умолчанию HTTP).
var HTTPSPorts = map[int]bool{443: true, 8443: true, 9443: true, 4443: true, 7443: true}

// TopWebPorts — топ веб-портов, пробиваемых когда у цели нет схемы и порта.
var TopWebPorts = []int{80, 443, 8080, 8443, 8000, 8888, 8081, 3000, 5000, 8008, 9000, 9443}

// ParsedTarget — цель после разбора (порт core.ParsedTarget).
type ParsedTarget struct {
	Hostname      string         // нормализованное имя хоста или строка IP
	IsIP          bool           // цель — IP-литерал
	ExplicitPorts map[int]string // port -> scheme
	HasExplicit   bool           // были явные порты/схема
}

// ProbeCandidate — кандидат на HTTP-пробив (порт core.ProbeCandidate).
type ProbeCandidate struct {
	Hostname string
	Port     int
	Scheme   string
	Inferred bool
}

// ResolveScheme — конфликт схемы на один (host, port): https побеждает.
func ResolveScheme(existing, next string, port int) string {
	if existing == "https" || next == "https" || HTTPSPorts[port] {
		return "https"
	}
	return "http"
}

// validHostname — процедурная замена _HOSTNAME_RE (в Go RE2 нет lookaround):
// суммарно ≤253, каждый лейбл 1..63 из [a-z0-9-], не начинается/кончается на '-'.
func validHostname(host string) bool {
	if len(host) < 1 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		n := len(label)
		if n < 1 || n > 63 {
			return false
		}
		if label[0] == '-' || label[n-1] == '-' {
			return false
		}
		for i := 0; i < n; i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// parsedToken — результат разбора одного токена.
type parsedToken struct {
	hostname string
	isIP     bool
	port     int // 0 = нет порта
	hasPort  bool
	scheme   string // "" = нет
}

// parseToken разбирает токен в (hostname, is_ip, port, scheme) или nil при невалиде.
func parseToken(token string) *parsedToken {
	raw := token
	if !strings.Contains(token, "://") {
		raw = "//" + token
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return nil // ftp:// и прочее — не веб
	}
	host := u.Hostname()
	if host == "" {
		return nil
	}
	host = strings.TrimRight(strings.ToLower(host), ".")
	if host == "" {
		return nil
	}
	var port int
	hasPort := false
	if ps := u.Port(); ps != "" {
		p, perr := strconv.Atoi(ps)
		if perr != nil {
			return nil
		}
		if p < 1 || p > 65535 {
			return nil
		}
		port, hasPort = p, true
	}

	isIP := false
	if IsIPLiteral(host) {
		isIP = true
	} else {
		ascii, ierr := idna.ToASCII(host)
		if ierr != nil {
			return nil
		}
		host = strings.ToLower(ascii)
		if !validHostname(host) {
			return nil
		}
	}

	if !hasPort {
		if scheme == "http" {
			port, hasPort = 80, true
		} else if scheme == "https" {
			port, hasPort = 443, true
		}
	}
	finalScheme := scheme
	if hasPort && finalScheme == "" {
		if HTTPSPorts[port] {
			finalScheme = "https"
		} else {
			finalScheme = "http"
		}
	}
	return &parsedToken{hostname: host, isIP: isIP, port: port, hasPort: hasPort, scheme: finalScheme}
}

var tokenSep = func(r rune) bool {
	return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ',' || r == '\f' || r == '\v'
}

// ParseTargets разбирает вставленный текст в упорядоченный список целей + ошибки
// (порт core.parse_targets). Порядок появления сохраняется (детерминизм).
func ParseTargets(raw string) ([]*ParsedTarget, []string) {
	order := []*ParsedTarget{}
	byName := map[string]*ParsedTarget{}
	var errors []string
	seenInvalid := map[string]bool{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		for _, token := range strings.FieldsFunc(line, tokenSep) {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			pt := parseToken(token)
			if pt == nil {
				if !seenInvalid[token] {
					seenInvalid[token] = true
					errors = append(errors, token+": не распознан как хост или URL")
				}
				continue
			}
			entry := byName[pt.hostname]
			if entry == nil {
				entry = &ParsedTarget{Hostname: pt.hostname, IsIP: pt.isIP, ExplicitPorts: map[int]string{}}
				byName[pt.hostname] = entry
				order = append(order, entry)
			}
			if pt.hasPort {
				entry.ExplicitPorts[pt.port] = ResolveScheme(entry.ExplicitPorts[pt.port], pt.scheme, pt.port)
				entry.HasExplicit = true
			}
		}
	}
	return order, errors
}

// ParseIPTargets — как ParseTargets, но имена хостов отклоняются с подсказкой
// (порт ips.IpFarmService.parse_ip_targets).
func ParseIPTargets(raw string) ([]*ParsedTarget, []string) {
	targets, errs := ParseTargets(raw)
	out := make([]*ParsedTarget, 0, len(targets))
	for _, t := range targets {
		if t.IsIP {
			out = append(out, t)
		} else {
			errs = append(errs, t.Hostname+": не IP-адрес — используйте импорт хостов")
		}
	}
	return out, errs
}

// CandidatesFor — явные порты как есть; иначе курируемый топ веб-портов
// (порт core.candidates_for). Явные — по возрастанию порта (детерминизм).
func CandidatesFor(t *ParsedTarget) []ProbeCandidate {
	if t.HasExplicit {
		ports := make([]int, 0, len(t.ExplicitPorts))
		for p := range t.ExplicitPorts {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		out := make([]ProbeCandidate, 0, len(ports))
		for _, p := range ports {
			out = append(out, ProbeCandidate{Hostname: t.Hostname, Port: p, Scheme: t.ExplicitPorts[p], Inferred: false})
		}
		return out
	}
	out := make([]ProbeCandidate, 0, len(TopWebPorts))
	for _, p := range TopWebPorts {
		scheme := "http"
		if HTTPSPorts[p] {
			scheme = "https"
		}
		out = append(out, ProbeCandidate{Hostname: t.Hostname, Port: p, Scheme: scheme, Inferred: true})
	}
	return out
}

// TrimExcessPorts обрезает явные порты сверх limit (оставляя младшие), возвращает
// ошибки (порт core.trim_excess_ports). Мутирует t.ExplicitPorts.
func TrimExcessPorts(targets []*ParsedTarget, limit int) []string {
	var errors []string
	for _, t := range targets {
		if t.HasExplicit && len(t.ExplicitPorts) > limit {
			ports := make([]int, 0, len(t.ExplicitPorts))
			for p := range t.ExplicitPorts {
				ports = append(ports, p)
			}
			sort.Ints(ports)
			for _, extra := range ports[limit:] {
				delete(t.ExplicitPorts, extra)
			}
			errors = append(errors, t.Hostname+": слишком много портов, оставлено "+strconv.Itoa(limit))
		}
	}
	return errors
}
