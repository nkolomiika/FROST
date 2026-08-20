package recon

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Scanner: раскрытие поддоменов (crt.sh + subfinder). Порт app/farm/subs.py.
// Чистые парсеры покрыты тестами; сбор подменяется SubCollector (сид для тестов).

// SubCollector — {root: (subs, sources_used, errors)} слитый по корням.
type SubCollector func(ctx context.Context, roots []string) (subs map[string]bool, used []string, errs []string)

// NormalizeRoot — имя к каноничному виду: lower, без точки на конце и '*.'-обёртки.
func NormalizeRoot(name string) string {
	name = strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	return name
}

// ParseRoots — корневые домены из вставленного текста (порт subs.parse_roots).
func ParseRoots(raw string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		for _, token := range strings.Fields(strings.ReplaceAll(line, ",", " ")) {
			name := NormalizeRoot(token)
			if name != "" && !IsIPLiteral(name) && strings.Contains(name, ".") && !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

// InScope — name принадлежит поддереву root (сам root тоже в scope).
func InScope(name, root string) bool {
	return name == root || strings.HasSuffix(name, "."+root)
}

// ParseCrtsh — поддомены из JSON-ответа crt.sh (порт parse_crtsh).
func ParseCrtsh(rawJSON, root string) []string {
	var data []map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(rawJSON)), &data); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, entry := range data {
		for _, field := range []string{"name_value", "common_name"} {
			value, ok := entry[field]
			if !ok || value == nil {
				continue
			}
			for _, piece := range strings.Split(strings.ReplaceAll(toStr(value), "\r\n", "\n"), "\n") {
				name := NormalizeRoot(piece)
				if name != "" && !IsIPLiteral(name) && InScope(name, root) && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// ParseSubfinder — поддомены из subfinder -silent (порт parse_subfinder).
func ParseSubfinder(text, root string) []string {
	seen := map[string]bool{}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		name := NormalizeRoot(line)
		if name != "" && !IsIPLiteral(name) && InScope(name, root) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// fetchCrtsh — crt.sh по корню (фиксированный хост, SSRF-transport не нужен).
func fetchCrtsh(ctx context.Context, root string, s Settings) ([]string, string) {
	c, cancel := context.WithTimeout(ctx, s.SubsCrtshTimeout)
	defer cancel()
	q := url.Values{"q": {"%." + root}, "output": {"json"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://crt.sh/?"+q.Encode(), nil)
	req = req.WithContext(c)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "crt.sh(" + root + "): " + errName(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "crt.sh(" + root + "): http_" + strconv.Itoa(resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, "crt.sh(" + root + "): " + errName(err)
	}
	return ParseCrtsh(string(body), root), ""
}

// runSubfinder — subfinder -d root -silent. Нет бинаря — тихо пропускаем.
func runSubfinder(ctx context.Context, root string, s Settings) ([]string, string) {
	if !lookPathOK(s.SubsSubfinderBin) {
		return nil, ""
	}
	c, cancel := context.WithTimeout(ctx, s.SubsSubfinderTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.SubsSubfinderBin, "-d", root, "-silent", "-no-color")
	out, err := cmd.Output()
	if err != nil {
		return nil, "subfinder(" + root + "): " + errName(err)
	}
	return ParseSubfinder(string(out), root), ""
}

// DefaultSubCollector — реальный сбор: crt.sh + subfinder по каждому корню.
func DefaultSubCollector(s Settings) SubCollector {
	return func(ctx context.Context, roots []string) (map[string]bool, []string, []string) {
		type rootOut struct {
			subs []string
			used []string
			errs []string
		}
		results := make([]rootOut, len(roots))
		var eg errgroup.Group
		eg.SetLimit(s.maxConcurrency())
		for i, root := range roots {
			i, root := i, root
			eg.Go(func() error {
				var ro rootOut
				if s.SubsCrtshEnabled {
					crt, e := fetchCrtsh(ctx, root, s)
					if len(crt) > 0 {
						ro.used = append(ro.used, "crt.sh")
					}
					ro.subs = append(ro.subs, crt...)
					if e != "" {
						ro.errs = append(ro.errs, e)
					}
				}
				if s.SubsSubfinderEnabled {
					sf, e := runSubfinder(ctx, root, s)
					if len(sf) > 0 {
						ro.used = append(ro.used, "subfinder")
					}
					ro.subs = append(ro.subs, sf...)
					if e != "" {
						ro.errs = append(ro.errs, e)
					}
				}
				results[i] = ro
				return nil
			})
		}
		_ = eg.Wait()

		subs := map[string]bool{}
		var used, errs []string
		usedSeen := map[string]bool{}
		for _, ro := range results {
			for _, sub := range ro.subs {
				subs[sub] = true
			}
			for _, u := range ro.used {
				if !usedSeen[u] {
					usedSeen[u] = true
					used = append(used, u)
				}
			}
			errs = append(errs, ro.errs...)
		}
		return subs, used, errs
	}
}

// SortedCapped — отсортированный срез ключей set, обрезанный до max.
func SortedCapped(set map[string]bool, max int) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}
