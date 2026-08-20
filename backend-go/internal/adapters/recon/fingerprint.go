package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// Определение технологий/CDN веб-порта внешними утилитами (порт farm/fingerprint.py).
// Бинари ходят на цель сами, в обход SSRF-transport, поэтому запускаются только по
// портам, уже ответившим на SSRF-защищённый пробив, и с ре-гейтом свежим резолвом.

// Tech — технология/сервис на порту (порт fingerprint.Tech).
type Tech struct {
	Name    string
	Version *string
}

// TechKey — ключ (hostname, port) детекта.
type TechKey struct {
	Host string
	Port int
}

// Detector — сид для тестов: urls → {url: [Tech]}.
type Detector func(ctx context.Context, urls []string) (map[string][]Tech, error)

// ForwardResolver — сид для тестов и точка ре-гейта перед выходом наружу.
type ForwardResolver func(ctx context.Context, hosts []string) map[string]ResolvedHost

var metaPlugins = map[string]bool{
	"Country": true, "IP": true, "Title": true, "Cookies": true, "UncommonHeaders": true,
	"RedirectLocation": true, "Meta-Author": true, "Meta-Refresh-Redirect": true,
	"MetaGenerator": true, "Script": true, "HTML5": true, "Email": true, "Frame": true,
	"X-Frame-Options": true, "X-XSS-Protection": true, "HttpOnly": true,
	"Strict-Transport-Security": true, "Content-Security-Policy": true, "X-UA-Compatible": true,
	"Access-Control-Allow-Origin": true, "Allow": true, "Via-Proxy": true, "probably": true,
}

// HasCloudflare — есть ли среди технологий Cloudflare (порт has_cloudflare).
func HasCloudflare(techs []Tech) bool {
	for _, t := range techs {
		if strings.Contains(strings.ToLower(t.Name), "cloudflare") {
			return true
		}
	}
	return false
}

func urlFor(p ProbeResult) string {
	host := p.Hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s://%s:%d/", p.Scheme, host, p.Port)
}

func urlKey(u string) TechKey {
	raw := u
	if !strings.Contains(u, "://") {
		raw = "//" + u
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return TechKey{}
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.ToLower(parsed.Hostname())
	port := 0
	if ps := parsed.Port(); ps != "" {
		port, _ = strconv.Atoi(ps)
	}
	if port == 0 {
		if scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}
	return TechKey{Host: host, Port: port}
}

func cap100(s string) string { return truncate(s, 100) }

// splitTech: 'Nginx:1.25.3' → Tech(Nginx,1.25.3); 'Cloudflare' → без версии.
func splitTech(raw string) Tech {
	s := strings.TrimSpace(raw)
	if i := strings.LastIndex(s, ":"); i >= 0 {
		name := strings.TrimSpace(s[:i])
		ver := strings.TrimSpace(s[i+1:])
		if name != "" && ver != "" && ver[0] >= '0' && ver[0] <= '9' {
			v := cap100(ver)
			return Tech{Name: cap100(name), Version: &v}
		}
	}
	return Tech{Name: cap100(s)}
}

func capitalizeFirst(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// ParseHttpxJSONL: httpx -json (JSONL) → {url: [Tech]} (порт parse_httpx_jsonl).
func ParseHttpxJSONL(raw string) map[string][]Tech {
	out := map[string][]Tech{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		u, _ := entry["input"].(string)
		if u == "" {
			u, _ = entry["url"].(string)
		}
		if u == "" {
			continue
		}
		order := []string{}
		techs := map[string]Tech{}
		if arr, ok := entry["tech"].([]any); ok {
			for _, item := range arr {
				t := splitTech(fmt.Sprintf("%v", item))
				key := strings.ToLower(t.Name)
				if _, exists := techs[key]; !exists {
					techs[key] = t
					order = append(order, key)
				}
			}
		}
		for _, extraKey := range []string{"webserver", "cdn_name"} {
			if val, ok := entry[extraKey]; ok {
				sval := fmt.Sprintf("%v", val)
				if sval != "" && val != nil {
					lk := strings.ToLower(sval)
					if _, exists := techs[lk]; !exists {
						techs[lk] = Tech{Name: cap100(capitalizeFirst(sval))}
						order = append(order, lk)
					}
				}
			}
		}
		list := make([]Tech, 0, len(order))
		for _, k := range order {
			list = append(list, techs[k])
		}
		out[u] = list
	}
	return out
}

func runHttpx(ctx context.Context, urls []string, s Settings) map[string][]Tech {
	timeout := s.ServicesDetectTimeout
	deadline := timeout + time.Duration(len(urls))*2*time.Second + 15*time.Second
	c, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	args := []string{
		"-json", "-silent", "-no-color", "-td", "-cdn",
		"-disable-update-check",
		"-timeout", strconv.Itoa(int(timeout.Seconds())),
		"-retries", "0",
	}
	cmd := exec.CommandContext(c, s.ServicesHttpxBin, args...)
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n"))
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return map[string][]Tech{}
	}
	return ParseHttpxJSONL(stdout.String())
}

// ParseWhatwebJSON — стек из whatweb --log-json для одной цели (порт parse_whatweb_json).
func ParseWhatwebJSON(raw string) []Tech {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var entries []map[string]any
	var top any
	if err := json.Unmarshal([]byte(raw), &top); err == nil {
		switch v := top.(type) {
		case []any:
			for _, e := range v {
				if m, ok := e.(map[string]any); ok {
					entries = append(entries, m)
				}
			}
		case map[string]any:
			entries = append(entries, v)
		}
	} else {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimRight(strings.TrimSpace(line), ",")
			if line == "" || line == "[" || line == "]" {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(line), &m) == nil {
				entries = append(entries, m)
			}
		}
	}

	order := []string{}
	techs := map[string]Tech{}
	for _, entry := range entries {
		plugins, _ := entry["plugins"].(map[string]any)
		for name, info := range plugins {
			if metaPlugins[name] {
				continue
			}
			var version *string
			var strs []string
			if m, ok := info.(map[string]any); ok {
				switch v := m["version"].(type) {
				case []any:
					if len(v) > 0 {
						vs := fmt.Sprintf("%v", v[0])
						version = &vs
					}
				case string:
					if v != "" {
						version = &v
					}
				}
				switch sv := m["string"].(type) {
				case []any:
					for _, x := range sv {
						strs = append(strs, fmt.Sprintf("%v", x))
					}
				case string:
					if sv != "" {
						strs = append(strs, sv)
					}
				}
			}
			label := name
			if (name == "HTTPServer" || name == "PoweredBy" || name == "X-Powered-By") && len(strs) > 0 {
				first := strings.TrimSpace(strings.SplitN(strs[0], "/", 2)[0])
				if first != "" {
					label = first
				}
			}
			key := strings.ToLower(label)
			existing, ok := techs[key]
			if !ok {
				techs[key] = Tech{Name: cap100(label), Version: version}
				order = append(order, key)
			} else if version != nil && existing.Version == nil {
				existing.Version = version
				techs[key] = existing
			}
		}
	}
	out := make([]Tech, 0, len(order))
	for _, k := range order {
		out = append(out, techs[k])
	}
	return out
}

func runWhatwebOne(ctx context.Context, u string, s Settings) []Tech {
	timeout := s.ServicesDetectTimeout
	c, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()
	secs := strconv.Itoa(int(timeout.Seconds()))
	args := []string{
		"--quiet", "--no-errors", "--follow-redirect=never",
		"--open-timeout", secs, "--read-timeout", secs,
		"--log-json=-", u,
	}
	cmd := exec.CommandContext(c, s.ServicesWhatwebBin, args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil
	}
	return ParseWhatwebJSON(stdout.String())
}

func runWhatweb(ctx context.Context, urls []string, s Settings) map[string][]Tech {
	out := map[string][]Tech{}
	results := make([][]Tech, len(urls))
	limit := s.ServicesMaxConcurrency
	if limit <= 0 {
		limit = 1
	}
	var eg errgroup.Group
	eg.SetLimit(limit)
	for i, u := range urls {
		i, u := i, u
		eg.Go(func() error { results[i] = runWhatwebOne(ctx, u, s); return nil })
	}
	_ = eg.Wait()
	for i, u := range urls {
		out[u] = results[i]
	}
	return out
}

// pickEngine — движок по настройке с фолбэком; nil — ни один бинарь не установлен.
func pickEngine(s Settings) Detector {
	httpxOK := lookPathOK(s.ServicesHttpxBin)
	whatwebOK := lookPathOK(s.ServicesWhatwebBin)
	if s.ServicesDetectEngine == "whatweb" && whatwebOK {
		return func(ctx context.Context, urls []string) (map[string][]Tech, error) {
			return runWhatweb(ctx, urls, s), nil
		}
	}
	if httpxOK {
		return func(ctx context.Context, urls []string) (map[string][]Tech, error) {
			return runHttpx(ctx, urls, s), nil
		}
	}
	if whatwebOK {
		return func(ctx context.Context, urls []string) (map[string][]Tech, error) {
			return runWhatweb(ctx, urls, s), nil
		}
	}
	return nil
}

func lookPathOK(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func regateExternal(ctx context.Context, responding []ProbeResult, resolve ForwardResolver) []ProbeResult {
	hostSet := map[string]bool{}
	var hosts []string
	for _, p := range responding {
		if !hostSet[p.Hostname] {
			hostSet[p.Hostname] = true
			hosts = append(hosts, p.Hostname)
		}
	}
	resolved := resolve(ctx, hosts)
	external := map[string]bool{}
	for h, r := range resolved {
		if r.IP != "" && !r.Blocked {
			external[h] = true
		}
	}
	out := make([]ProbeResult, 0, len(responding))
	for _, p := range responding {
		if external[p.Hostname] {
			out = append(out, p)
		}
	}
	return out
}

// DetectServices — технологии ответивших портов: {(hostname, port): [Tech]}
// (порт detect_services). detector/resolver — сиды для тестов; в проде nil.
func DetectServices(ctx context.Context, probes []ProbeResult, s Settings, detector Detector, resolve ForwardResolver) map[TechKey][]Tech {
	var responding []ProbeResult
	for _, p := range probes {
		if p.Responded {
			responding = append(responding, p)
		}
	}
	if len(responding) == 0 {
		return map[TechKey][]Tech{}
	}

	run := detector
	if run == nil {
		if !s.ServicesDetectEnabled {
			return map[TechKey][]Tech{}
		}
		run = pickEngine(s)
		if run == nil {
			return map[TechKey][]Tech{}
		}
		if resolve == nil && !s.FarmAllowPrivate {
			resolve = func(c context.Context, hosts []string) map[string]ResolvedHost { return ResolveForward(c, hosts, s) }
		}
	}

	if resolve != nil {
		responding = regateExternal(ctx, responding, resolve)
		if len(responding) == 0 {
			return map[TechKey][]Tech{}
		}
	}

	urls := make([]string, 0, len(responding))
	for _, p := range responding {
		urls = append(urls, urlFor(p))
	}
	engineOut, err := run(ctx, urls)
	if err != nil {
		engineOut = map[string][]Tech{}
	}
	byKey := map[TechKey][]Tech{}
	for u, techs := range engineOut {
		byKey[urlKey(u)] = techs
	}
	out := map[TechKey][]Tech{}
	for _, p := range responding {
		techs := byKey[urlKey(urlFor(p))]
		if techs == nil {
			techs = []Tech{} // default [] (порт by_key.get(..., [])): детект прошёл, чистим сервисы
		}
		out[TechKey{Host: p.Hostname, Port: p.Port}] = techs
	}
	return out
}
