package recon

import "strings"

// multiSLD — второй уровень публичного суффикса: <SLD>.<двухбуквенный ccTLD>
// (co.uk, com.hk, com.au, co.jp, gov.uk…). Зеркало фронтового MULTI_SLD в
// FrostApp.tsx — держим списки согласованными, чтобы группировка в дереве хостов
// и серверный пробив корня считали eTLD+1 одинаково.
var multiSLD = map[string]bool{
	"co": true, "com": true, "net": true, "org": true, "edu": true, "gov": true,
	"gob": true, "gouv": true, "mil": true, "ac": true, "go": true, "or": true,
	"ne": true, "ad": true, "in": true, "ltd": true, "plc": true, "web": true,
	"sch": true, "nic": true, "nom": true,
}

// RegistrableDomain — регистрируемый домен (eTLD+1): apuat9.prudential.com.hk →
// prudential.com.hk, www.acme.com → acme.com. IP-литералы и пустые строки
// возвращаются как есть (вызывающий сам решает, что с ними делать).
func RegistrableDomain(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || IsIPLiteral(host) {
		return host
	}
	var labels []string
	for _, l := range strings.Split(host, ".") {
		if l != "" {
			labels = append(labels, l)
		}
	}
	if len(labels) <= 2 {
		return strings.Join(labels, ".")
	}
	tld := labels[len(labels)-1]
	sld := labels[len(labels)-2]
	take := 2
	if len(tld) == 2 && multiSLD[sld] {
		take = 3
	}
	return strings.Join(labels[len(labels)-take:], ".")
}

// WithRegistrableRoots дополняет список целей регистрируемыми корнями (eTLD+1)
// каждого доменного (не-IP) хоста, которых ещё нет в списке. Корню порт/схему не
// задаём — пробивается стандартным веб-набором. Порядок стабилен: сперва исходные
// цели, затем добавленные корни. Так «Add hosts» из списка поддоменов заодно
// заводит и пробивает сам основной домен, а не оставляет пустую шапку в дереве.
func WithRegistrableRoots(targets []*ParsedTarget) []*ParsedTarget {
	seen := map[string]bool{}
	for _, t := range targets {
		seen[t.Hostname] = true
	}
	out := targets
	for _, t := range targets {
		if t.IsIP {
			continue
		}
		r := RegistrableDomain(t.Hostname)
		if r == "" || r == t.Hostname || seen[r] || IsIPLiteral(r) {
			continue
		}
		seen[r] = true
		out = append(out, &ParsedTarget{Hostname: r, IsIP: false, ExplicitPorts: map[int]string{}})
	}
	return out
}
