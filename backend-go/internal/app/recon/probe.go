package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// probeAll — HTTP-пробив целей с валидным внешним адресом (порт _probe_all).
func (s *Service) probeAll(ctx context.Context, targets []*reconnet.ParsedTarget, resolved map[string]reconnet.ResolvedHost) []reconnet.ProbeResult {
	var candidates []reconnet.ProbeCandidate
	for _, t := range targets {
		r, ok := resolved[t.Hostname]
		if !ok || r.IP == "" || r.Blocked {
			continue
		}
		candidates = append(candidates, reconnet.CandidatesFor(t)...)
	}
	return reconnet.ProbeCandidates(ctx, candidates, s.settings)
}

func groupProbes(probes []reconnet.ProbeResult) map[string][]reconnet.ProbeResult {
	out := map[string][]reconnet.ProbeResult{}
	for _, p := range probes {
		out[p.Hostname] = append(out[p.Hostname], p)
	}
	return out
}

func statusFor(blocked, responded bool) string {
	if blocked {
		return statusUNKNOWN
	}
	if responded {
		return statusUP
	}
	return statusDOWN
}

// buildPorts — из пробивов хоста строит записи для persist и порты для result
// (порт _write_ports: явные пишем всегда, выведенные — только ответившие).
func buildPorts(hostProbes []reconnet.ProbeResult, techsByPort map[reconnet.TechKey][]reconnet.Tech) ([]PortWrite, []PortResult) {
	writes := make([]PortWrite, 0, len(hostProbes))
	results := make([]PortResult, 0, len(hostProbes))
	for _, p := range hostProbes {
		if !p.Responded && p.Inferred {
			continue
		}
		state := stateFILTERED
		if p.Responded {
			state = stateOPEN
		}
		techs, ok := techsByPort[reconnet.TechKey{Host: p.Hostname, Port: p.Port}]
		writes = append(writes, PortWrite{
			PortNumber: int32(p.Port), State: state, HTTPStatus: intPtr(p.HTTPStatus), Techs: techs, HasTechs: ok,
		})
		results = append(results, PortResult{
			PortNumber: int32(p.Port), Protocol: "tcp", Scheme: p.Scheme,
			HTTPStatus: intPtr(p.HTTPStatus), State: strings.ToLower(state), Inferred: p.Inferred,
		})
	}
	return writes, results
}

func cloudflareHint(hostProbes []reconnet.ProbeResult, techsByPort map[reconnet.TechKey][]reconnet.Tech) bool {
	var allTechs []reconnet.Tech
	for _, p := range hostProbes {
		if p.Cloudflare {
			return true
		}
		allTechs = append(allTechs, techsByPort[reconnet.TechKey{Host: p.Hostname, Port: p.Port}]...)
	}
	return reconnet.HasCloudflare(allTechs)
}

func intPtr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := int32(*p)
	return &v
}

// ─────────────────────────── hosts ───────────────────────────

func (s *Service) probeHosts(ctx context.Context, projectID, actorID int32, raw string, skip []string, resolveIPs bool) (*HostFarmResult, error) {
	targets, parseErrors := reconnet.ParseTargets(raw)
	if len(targets) > s.settings.FarmMaxTargets {
		return nil, apperr.Validation(fmt.Sprintf("Слишком много хостов: %d (максимум %d)", len(targets), s.settings.FarmMaxTargets))
	}
	skipSet := toSet(skip)
	skipped := 0
	kept := targets[:0]
	for _, t := range targets {
		if skipSet[t.Hostname] {
			skipped++
			continue
		}
		kept = append(kept, t)
	}
	targets = kept
	parseErrors = append(parseErrors, reconnet.TrimExcessPorts(targets, s.settings.FarmMaxPortsPerHost)...)

	resolved := reconnet.ResolveForward(ctx, targetKeys(targets), s.settings)
	probes := s.probeAll(ctx, targets, resolved)
	techsByPort := reconnet.DetectServices(ctx, probes, s.settings, s.detector, s.resolverSeam)
	result := s.persistHosts(ctx, projectID, actorID, targets, resolved, probes, techsByPort)

	result.TargetsParsed = len(targets)
	result.TargetsInvalid = countInvalid(parseErrors, ": не распознан")
	result.HostsSkipped = skipped
	result.Errors = append(parseErrors, resolveErrors(resolved)...)

	if resolveIPs && s.settings.FarmHostResolveIPsEnabled {
		ipSet := map[string]bool{}
		for _, t := range targets {
			if t.IsIP {
				continue
			}
			r, ok := resolved[t.Hostname]
			if ok && r.IP != "" && !r.Blocked {
				ipSet[r.IP] = true
			}
		}
		if len(ipSet) > 0 {
			ips := sortedSet(ipSet)
			ipRes, err := s.probeIPs(ctx, projectID, actorID, strings.Join(ips, "\n"), nil, false)
			if err != nil {
				return nil, err
			}
			result.IPsPromoted = ipRes.IPsCreated + ipRes.IPsUpdated
			result.Errors = append(result.Errors, ipRes.Errors...)
		}
	}
	return result, nil
}

func (s *Service) persistHosts(ctx context.Context, projectID, actorID int32, targets []*reconnet.ParsedTarget, resolved map[string]reconnet.ResolvedHost, probes []reconnet.ProbeResult, techsByPort map[reconnet.TechKey][]reconnet.Tech) *HostFarmResult {
	result := newHostFarmResult()
	byHost := groupProbes(probes)
	for _, t := range targets {
		r, hasR := resolved[t.Hostname]
		hostProbes := byHost[t.Hostname]
		responded := anyResponded(hostProbes)
		status := statusFor(hasR && r.Blocked, responded)

		writes, portResults := buildPorts(hostProbes, techsByPort)
		in := HostPersistInput{
			ProjectID: projectID, IsIP: t.IsIP, TargetKey: t.Hostname, Status: status,
			IPs: ipsOf(r), Blocked: hasR && r.Blocked, HasIP: hasR && r.IP != "",
			CloudflareHint: cloudflareHint(hostProbes, techsByPort), CFResponded: responded, Ports: writes,
		}
		out, err := s.store.PersistHost(ctx, in)
		if err != nil {
			result.Errors = append(result.Errors, t.Hostname+": "+reconnet.ErrLabel(err))
			continue
		}
		if out.Created {
			result.HostsCreated++
		} else {
			result.HostsUpdated++
		}
		if status == statusUP {
			result.HostsOnline++
		} else if status == statusDOWN {
			result.HostsOffline++
		}
		result.PortsCreated += out.PortsCreated
		result.PortsUpdated += out.PortsUpdated
		result.Hosts = append(result.Hosts, HostResult{
			Hostname: out.FinalHostname, IPAddress: out.FinalIPAddress,
			Status: lowerStatus(status), Created: out.Created, Ports: portResults,
		})
	}
	s.audit(ctx, actorID, "host_farm", detailsFromItems(result, projectID, "hosts", hostFarmNames(result.Hosts)))
	return result
}

// ─────────────────────────── ips ───────────────────────────

func (s *Service) probeIPs(ctx context.Context, projectID, actorID int32, raw string, skip []string, resolveHosts bool) (*IpFarmResult, error) {
	targets, parseErrors := reconnet.ParseIPTargets(raw)
	if len(targets) > s.settings.FarmMaxTargets {
		return nil, apperr.Validation(fmt.Sprintf("Слишком много IP: %d (максимум %d)", len(targets), s.settings.FarmMaxTargets))
	}
	skipSet := toSet(skip)
	skipped := 0
	kept := targets[:0]
	for _, t := range targets {
		if skipSet[t.Hostname] {
			skipped++
			continue
		}
		kept = append(kept, t)
	}
	targets = kept
	parseErrors = append(parseErrors, reconnet.TrimExcessPorts(targets, s.settings.FarmMaxPortsPerHost)...)

	projectHostnames, err := s.store.ProjectAllHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	keys := targetKeys(targets)
	resolved := reconnet.ResolveForward(ctx, keys, s.settings)
	reverse := reconnet.ReverseResolve(ctx, keys, projectHostnames, s.settings)
	probes := s.probeAll(ctx, targets, resolved)
	techsByPort := reconnet.DetectServices(ctx, probes, s.settings, s.detector, s.resolverSeam)
	result := s.persistIPs(ctx, projectID, actorID, targets, resolved, reverse, probes, techsByPort)

	result.TargetsParsed = len(targets)
	result.TargetsInvalid = countInvalid(parseErrors, ": не распознан", ": не IP-адрес")
	result.IPsSkipped = skipped
	result.Errors = append(parseErrors, resolveErrors(resolved)...)

	if resolveHosts && s.settings.FarmIPResolveHostsEnabled {
		promotedSet := map[string]bool{}
		for _, rev := range reverse {
			for _, n := range rev.Names {
				if n.Confirmed {
					promotedSet[n.Hostname] = true
				}
			}
		}
		if len(promotedSet) > 0 {
			promoted := sortedSet(promotedSet)
			hostRes, err := s.probeHosts(ctx, projectID, actorID, strings.Join(promoted, "\n"), nil, false)
			if err != nil {
				return nil, err
			}
			result.HostsPromoted = hostRes.HostsCreated + hostRes.HostsUpdated
			result.Errors = append(result.Errors, hostRes.Errors...)
		}
	}
	return result, nil
}

func (s *Service) persistIPs(ctx context.Context, projectID, actorID int32, targets []*reconnet.ParsedTarget, resolved map[string]reconnet.ResolvedHost, reverse map[string]reconnet.ReverseResult, probes []reconnet.ProbeResult, techsByPort map[reconnet.TechKey][]reconnet.Tech) *IpFarmResult {
	result := newIpFarmResult()
	byIP := groupProbes(probes)
	for _, t := range targets {
		ip := t.Hostname
		r, hasR := resolved[ip]
		rev := reverse[ip]
		ipProbes := byIP[ip]
		responded := anyResponded(ipProbes)
		status := statusFor(hasR && r.Blocked, responded)

		writes, portResults := buildPorts(ipProbes, techsByPort)
		hostnames := hostnameOuts(rev.Names)
		in := IPPersistInput{
			ProjectID: projectID, IP: ip, Status: status, Blocked: hasR && r.Blocked,
			HasIP: hasR && r.IP != "", CloudflareHint: cloudflareHint(ipProbes, techsByPort),
			CFResponded: responded, Hostnames: hostnames, Ports: writes,
		}
		out, err := s.store.PersistIP(ctx, in)
		if err != nil {
			result.Errors = append(result.Errors, ip+": "+reconnet.ErrLabel(err))
			continue
		}
		if out.IPExisted {
			result.IPsUpdated++
		} else {
			result.IPsCreated++
		}
		if status == statusUP {
			result.IPsOnline++
		} else if status == statusDOWN {
			result.IPsOffline++
		}
		result.HostnamesFound += len(rev.Names)
		result.PortsCreated += out.PortsCreated
		result.PortsUpdated += out.PortsUpdated
		hostID := out.HostID
		result.IPs = append(result.IPs, IPResult{
			IPAddress: ip, HostID: &hostID, Hostnames: hostnames, IsCloudflare: out.IsCloudflare,
			Created: out.HostCreated, AttachedToExistingHost: out.Attached, Ports: portResults,
		})
	}
	s.audit(ctx, actorID, "ip_farm", detailsFromItems(result, projectID, "ips", ipFarmNames(result.IPs)))
	return result
}

func hostnameOuts(names []reconnet.ResolvedName) []HostnameOut {
	out := make([]HostnameOut, 0, len(names))
	for _, n := range names {
		out = append(out, HostnameOut{Hostname: n.Hostname, Source: n.Source, Confirmed: n.Confirmed})
	}
	return out
}

// ─────────────────────────── ports (nmap) ───────────────────────────

func (s *Service) probePorts(ctx context.Context, projectID, actorID int32, raw string, skip []string) (*PortScanResult, error) {
	targets, parseErrors := reconnet.ParseTargets(raw)
	if len(targets) > s.settings.PortscanMaxTargets {
		return nil, apperr.Validation(fmt.Sprintf("Слишком много целей: %d (максимум %d)", len(targets), s.settings.PortscanMaxTargets))
	}
	skipSet := toSet(skip)
	kept := targets[:0]
	for _, t := range targets {
		if !skipSet[t.Hostname] {
			kept = append(kept, t)
		}
	}
	targets = kept

	resolved := reconnet.ResolveForward(ctx, targetKeys(targets), s.settings)
	scanIPSet := map[string]bool{}
	for _, r := range resolved {
		if r.IP != "" && !r.Blocked {
			scanIPSet[r.IP] = true
		}
	}
	scanIPs := sortedSet(scanIPSet)
	scanner := s.scanner
	if scanner == nil {
		scanner = reconnet.DefaultNmapScanner(s.settings)
	}
	scan, scanErr := scanner(ctx, scanIPs)

	result := s.persistScan(ctx, projectID, actorID, targets, resolved, scan)
	result.TargetsScanned = len(targets)
	result.TargetsInvalid = countInvalid(parseErrors, ": не распознан")
	errs := append(parseErrors, resolveErrors(resolved)...)
	errs = append(errs, result.Errors...)
	if scanErr != "" {
		errs = append(errs, scanErr)
	}
	result.Errors = errs
	return result, nil
}

func (s *Service) persistScan(ctx context.Context, projectID, actorID int32, targets []*reconnet.ParsedTarget, resolved map[string]reconnet.ResolvedHost, scan map[string][]int) *PortScanResult {
	result := newPortScanResult()
	for _, t := range targets {
		r, hasR := resolved[t.Hostname]
		if !hasR || r.IP == "" || r.Blocked {
			continue
		}
		openPorts := scan[r.IP]
		status := statusDOWN
		if len(openPorts) > 0 {
			status = statusUP
		}
		out, err := s.store.PersistScanHost(ctx, ScanHostInput{
			ProjectID: projectID, IsIP: t.IsIP, TargetKey: t.Hostname, Status: status, IPs: ipsOf(r), OpenPorts: openPorts,
		})
		if err != nil {
			result.Errors = append(result.Errors, t.Hostname+": "+reconnet.ErrLabel(err))
			continue
		}
		if len(openPorts) > 0 {
			result.HostsUp++
		}
		result.PortsFound += len(openPorts)
		result.PortsCreated += out.PortsCreated
		result.PortsUpdated += out.PortsUpdated
		result.Hosts = append(result.Hosts, PortScanHostResult{
			Hostname: out.FinalHostname, IPAddress: out.FinalIPAddress, OpenPorts: orEmptyInts(openPorts),
		})
	}
	s.audit(ctx, actorID, "port_scan", detailsFrom(result, projectID, "hosts"))
	return result
}

// ─────────────────────────── subs ───────────────────────────

func (s *Service) probeSubs(ctx context.Context, projectID, actorID int32, raw string) (*SubFarmResult, error) {
	roots, err := s.subsRoots(ctx, projectID, raw)
	if err != nil {
		return nil, err
	}
	result := newSubFarmResult()
	if len(roots) == 0 {
		return result, nil
	}
	collector := s.collector
	if collector == nil {
		collector = reconnet.DefaultSubCollector(s.settings)
	}
	subsSet, sourcesUsed, errors := collector(ctx, roots)
	capped := reconnet.SortedCapped(subsSet, s.settings.SubsMaxResults)

	existingRows, err := s.store.ProjectAllHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	existing := map[string]bool{}
	for _, h := range existingRows {
		if n := reconnet.NormalizeRoot(h); n != "" {
			existing[n] = true
		}
	}
	var newSubs []string
	for _, sub := range capped {
		if !existing[sub] {
			newSubs = append(newSubs, sub)
		}
	}

	result.RootsScanned = len(roots)
	result.SubdomainsFound = len(capped)
	result.SubdomainsNew = len(newSubs)
	result.SourcesUsed = orEmpty(sourcesUsed)
	result.Subdomains = orEmpty(capped)
	result.Errors = orEmpty(errors)

	if len(newSubs) > 0 {
		hostRes, err := s.probeHosts(ctx, projectID, actorID, strings.Join(newSubs, "\n"), nil, true)
		if err != nil {
			return nil, err
		}
		result.HostsCreated = hostRes.HostsCreated
		result.HostsOnline = hostRes.HostsOnline
		result.HostsOffline = hostRes.HostsOffline
		result.Errors = append(result.Errors, hostRes.Errors...)
	}
	s.audit(ctx, actorID, "sub_farm", detailsFrom(result, projectID, "subdomains"))
	return result, nil
}

// ─────────────────────────── reverse ───────────────────────────

func (s *Service) probeReverse(ctx context.Context, projectID, actorID int32, raw string, skip []string) (*ReverseFarmResult, error) {
	ips, err := s.reverseTargets(ctx, projectID, raw)
	if err != nil {
		return nil, err
	}
	result := newReverseFarmResult()
	if len(ips) == 0 {
		return result, nil
	}
	ipRes, err := s.probeIPs(ctx, projectID, actorID, strings.Join(ips, "\n"), skip, true)
	if err != nil {
		return nil, err
	}
	result.IPsScanned = len(ips)
	result.HostnamesFound = ipRes.HostnamesFound
	result.HostsDiscovered = ipRes.HostsPromoted
	result.Errors = orEmpty(ipRes.Errors)
	s.audit(ctx, actorID, "reverse_farm", detailsFrom(result, projectID))
	return result, nil
}

// ─────────────────────────── js ───────────────────────────

func (s *Service) probeJS(ctx context.Context, projectID, actorID int32, raw string) (*JsFarmResult, error) {
	domains, err := s.jsDomains(ctx, projectID, raw)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return newJsFarmResult(), nil
	}
	files, errors := reconnet.DiscoverAndScan(ctx, domains, s.settings)
	return s.persistJS(ctx, projectID, actorID, files, errors)
}

func (s *Service) persistJS(ctx context.Context, projectID, actorID int32, files []reconnet.ScannedFile, errors []string) (*JsFarmResult, error) {
	result := newJsFarmResult()
	result.Errors = orEmpty(errors)
	hostMap, err := s.store.ProjectOriginHostMap(ctx, projectID)
	if err != nil {
		return nil, err
	}
	domainSet := map[string]bool{}
	for _, f := range files {
		domainSet[f.Hostname] = true
	}
	result.DomainsScanned = len(domainSet)
	result.FilesFound = len(files)

	for _, f := range files {
		hostID, ok := hostMap[strings.ToLower(f.Hostname)]
		if !ok {
			result.Errors = append(result.Errors, f.Hostname+": хост не найден")
			continue
		}
		secrets := make([]JSSecretInput, 0, len(f.Secrets))
		for _, sec := range f.Secrets {
			secrets = append(secrets, JSSecretInput{Kind: sec.Kind, MatchPreview: sec.MatchPreview, Snippet: sec.Snippet, Severity: sec.Severity})
		}
		in := JSFileInput{
			ProjectID: projectID, HostID: hostID, URL: f.URL, Status: f.Status, Error: f.Error,
			SHA256: f.SHA256, SizeBytes: f.SizeBytes, ContentType: f.ContentType,
			Endpoints: orEmpty(f.Endpoints), SecretCount: int32(len(f.Secrets)), EndpointCount: int32(len(f.Endpoints)),
			Secrets: secrets,
		}
		if err := s.store.PersistJSFile(ctx, in); err != nil {
			result.Errors = append(result.Errors, f.URL+": "+reconnet.ErrLabel(err))
			continue
		}
		if f.Status == "ok" {
			result.FilesScanned++
		} else {
			result.FilesFailed++
		}
		result.SecretsFound += len(f.Secrets)
		result.EndpointsFound += len(f.Endpoints)
		result.Files = append(result.Files, JSFileResult{
			URL: f.URL, Hostname: f.Hostname, Status: f.Status,
			SecretCount: len(f.Secrets), EndpointCount: len(f.Endpoints),
		})
	}
	s.audit(ctx, actorID, "js_farm", detailsFromItems(result, projectID, "files", jsFarmNames(result.Files)))
	return result, nil
}

// ─────────────────────────── shared helpers ───────────────────────────

func (s *Service) audit(ctx context.Context, actorID int32, entity string, details []byte) {
	id := actorID
	_ = s.store.InsertAudit(ctx, AuditEntry{UserID: &id, Action: "CREATE", EntityType: entity, Details: details})
}

func anyResponded(probes []reconnet.ProbeResult) bool {
	for _, p := range probes {
		if p.Responded {
			return true
		}
	}
	return false
}

func ipsOf(r reconnet.ResolvedHost) []string {
	if len(r.IPs) > 0 {
		return r.IPs
	}
	if r.IP != "" {
		return []string{r.IP}
	}
	return nil
}

func resolveErrors(resolved map[string]reconnet.ResolvedHost) []string {
	// Порядок ошибок в Python — по значениям dict (недетерминирован); сортируем
	// для стабильности вывода.
	var out []string
	for _, r := range resolved {
		if r.Error != "" {
			out = append(out, r.Error)
		}
	}
	sort.Strings(out)
	return out
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orEmptyInts(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}
