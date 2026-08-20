package recon

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Провенанс имени: PTR-запись адреса либо имя известного в проекте хоста.
const (
	SourcePTR     = "ptr"
	SourceProject = "project"
)

var sourceRank = map[string]int{SourcePTR: 0, SourceProject: 1}

// resolver — DNS-резолвер (переопределяется в тестах при необходимости).
var resolver = net.DefaultResolver

// ResolvedHost — результат прямого резолва (порт resolver.ResolvedHost).
// IP=="" эквивалентно Python ip=None.
type ResolvedHost struct {
	IP      string
	IPs     []string
	Blocked bool
	Error   string
}

// ResolvedName — имя, в которое резолвится адрес (порт resolver.ResolvedName).
type ResolvedName struct {
	Hostname  string
	Source    string
	Confirmed bool
}

// ReverseResult — имена одного IP из обратного резолва (порт resolver.ReverseResult).
type ReverseResult struct {
	IP    string
	Names []ResolvedName
	Error string
}

// IsIPLiteral — валидный IPv4/IPv6-литерал (порт resolver.is_ip_literal).
func IsIPLiteral(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}

// orderAddrs — все адреса без дублей: сначала IPv4, затем IPv6 (порт order_addrs).
func orderAddrs(addrs []netip.Addr) []string {
	var v4, v6 []string
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			v4 = append(v4, a.Unmap().String())
		} else {
			v6 = append(v6, a.String())
		}
	}
	ordered := append(v4, v6...)
	seen := map[string]bool{}
	out := make([]string, 0, len(ordered))
	for _, a := range ordered {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// ResolveForward резолвит имена в адреса (порт resolve_forward). IP-литералы не
// резолвятся, но проходят SSRF-гейт.
func ResolveForward(ctx context.Context, hostnames []string, s Settings) map[string]ResolvedHost {
	out := make(map[string]ResolvedHost, len(hostnames))
	results := make([]ResolvedHost, len(hostnames))
	allowPrivate := s.FarmAllowPrivate

	var eg errgroup.Group
	eg.SetLimit(s.maxConcurrency())
	for i, host := range hostnames {
		i, host := i, host
		eg.Go(func() error {
			var addrs []string
			if IsIPLiteral(host) {
				addrs = []string{host}
			} else {
				infos, err := resolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					results[i] = ResolvedHost{Error: host + ": DNS не разрешается"}
					return nil
				}
				addrs = orderAddrs(infos)
			}
			if len(addrs) == 0 {
				results[i] = ResolvedHost{Error: host + ": DNS не разрешается"}
				return nil
			}
			addr := addrs[0]
			if !allowPrivate && IsDisallowedIP(addr) {
				results[i] = ResolvedHost{IP: addr, IPs: addrs, Blocked: true, Error: host + " → внутренний IP " + addr + ": пробив пропущен"}
				return nil
			}
			results[i] = ResolvedHost{IP: addr, IPs: addrs}
			return nil
		})
	}
	_ = eg.Wait()
	for i, host := range hostnames {
		out[host] = results[i]
	}
	return out
}

// mergeNames — дедуп по имени: confirmed=OR, ptr над project; сортировка:
// подтверждённые выше, затем ptr над project, затем по алфавиту (порт merge_names).
func mergeNames(names []ResolvedName) []ResolvedName {
	order := []string{}
	merged := map[string]*ResolvedName{}
	for _, n := range names {
		cur := merged[n.Hostname]
		if cur == nil {
			cp := ResolvedName{Hostname: n.Hostname, Source: n.Source, Confirmed: n.Confirmed}
			merged[n.Hostname] = &cp
			order = append(order, n.Hostname)
			continue
		}
		cur.Confirmed = cur.Confirmed || n.Confirmed
		if sourceRank[n.Source] < sourceRank[cur.Source] {
			cur.Source = n.Source
		}
	}
	out := make([]ResolvedName, 0, len(order))
	for _, h := range order {
		out = append(out, *merged[h])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confirmed != out[j].Confirmed {
			return out[i].Confirmed // подтверждённые выше
		}
		if sourceRank[out[i].Source] != sourceRank[out[j].Source] {
			return sourceRank[out[i].Source] < sourceRank[out[j].Source]
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

// normalizeName — lower + rstrip('.').
func normalizeName(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}

// ReverseResolve определяет, в какие имена резолвится каждый IP: PTR +
// forward-confirm + сверка с именами хостов проекта (порт reverse_resolve).
func ReverseResolve(ctx context.Context, ips []string, projectHostnames []string, s Settings) map[string]ReverseResult {
	results := make(map[string]ReverseResult, len(ips))
	for _, ip := range ips {
		results[ip] = ReverseResult{IP: ip}
	}
	if !s.FarmReverseDNSEnabled || len(ips) == 0 {
		return results
	}
	timeout := s.FarmReverseDNSTimeout
	limit := s.maxConcurrency()

	ptrNames := func(ip string) []string {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		raw, err := resolver.LookupAddr(c, ip)
		if err != nil {
			return nil
		}
		seen := map[string]bool{}
		var names []string
		for _, n := range raw {
			name := normalizeName(n)
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
		return names
	}
	addrsOf := func(host string) map[string]bool {
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		infos, err := resolver.LookupNetIP(c, "ip", host)
		if err != nil {
			return map[string]bool{}
		}
		set := map[string]bool{}
		for _, a := range orderAddrs(infos) {
			set[a] = true
		}
		return set
	}

	// Фаза A: PTR для каждого адреса.
	ptrByIP := make([]([]string), len(ips))
	{
		var eg errgroup.Group
		eg.SetLimit(limit)
		for i, ip := range ips {
			i, ip := i, ip
			eg.Go(func() error { ptrByIP[i] = ptrNames(ip); return nil })
		}
		_ = eg.Wait()
	}

	// Фаза B: прямой резолв кандидатов (PTR-имена + имена проекта) одним пулом.
	projectSet := map[string]bool{}
	for _, h := range projectHostnames {
		if n := normalizeName(h); n != "" {
			projectSet[n] = true
		}
	}
	candSet := map[string]bool{}
	for _, names := range ptrByIP {
		for _, n := range names {
			candSet[n] = true
		}
	}
	for n := range projectSet {
		candSet[n] = true
	}
	candidates := make([]string, 0, len(candSet))
	for n := range candSet {
		candidates = append(candidates, n)
	}
	sort.Strings(candidates)
	forwardSets := make([]map[string]bool, len(candidates))
	{
		var eg errgroup.Group
		eg.SetLimit(limit)
		for i, h := range candidates {
			i, h := i, h
			eg.Go(func() error { forwardSets[i] = addrsOf(h); return nil })
		}
		_ = eg.Wait()
	}
	forward := make(map[string]map[string]bool, len(candidates))
	for i, h := range candidates {
		forward[h] = forwardSets[i]
	}

	for i, ip := range ips {
		names := ptrByIP[i]
		collected := make([]ResolvedName, 0, len(names))
		for _, name := range names {
			collected = append(collected, ResolvedName{Hostname: name, Source: SourcePTR, Confirmed: forward[name] != nil && forward[name][ip]})
		}
		// Имена проекта, резолвящиеся в этот адрес — подтверждены по построению.
		projNames := make([]string, 0)
		for name := range projectSet {
			if forward[name] != nil && forward[name][ip] {
				projNames = append(projNames, name)
			}
		}
		sort.Strings(projNames)
		for _, name := range projNames {
			collected = append(collected, ResolvedName{Hostname: name, Source: SourceProject, Confirmed: true})
		}
		results[ip] = ReverseResult{IP: ip, Names: mergeNames(collected)}
	}
	return results
}

// AsMap — имя в форме {hostname, source, confirmed} (порт ResolvedName.as_dict).
func (n ResolvedName) AsMap() map[string]any {
	return map[string]any{"hostname": n.Hostname, "source": n.Source, "confirmed": n.Confirmed}
}
