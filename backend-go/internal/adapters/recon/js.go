package recon

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
)

// Ферма JS: discover .js на доменах, download (с капом), греп секретов/путей.
// Порт app/farm/js.py фаз discover+download+archive (без БД).

// ScannedFile — итог скана одного .js (порт js.ScannedFile).
type ScannedFile struct {
	URL         string
	Hostname    string
	Status      string // ok | failed | too_large
	Error       string
	SHA256      string
	SizeBytes   *int32
	ContentType string
	Secrets     []Secret
	Endpoints   []string
}

// jsFetch — GET с капом размера. status: ok | too_large | failed (порт JsFarmService._fetch).
func jsFetch(ctx context.Context, client *http.Client, target string, maxBytes int) (ctype string, body []byte, status, errStr string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", nil, "failed", errName(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, "failed", errName(err)
	}
	defer resp.Body.Close()
	ctype = resp.Header.Get("Content-Type")
	if resp.StatusCode >= 400 {
		return ctype, nil, "failed", "http_" + strconv.Itoa(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBytes)+1))
	if err != nil {
		return ctype, nil, "failed", errName(err)
	}
	if len(data) > maxBytes {
		return ctype, nil, "too_large", ""
	}
	return ctype, data, "ok", ""
}

// DiscoverAndScan — фазы 2–3 без БД: находит .js по доменам, качает и грепает
// (порт JsFarmService._discover_and_scan).
func DiscoverAndScan(ctx context.Context, domains []string, s Settings) ([]ScannedFile, []string) {
	resolved := ResolveForward(ctx, domains, s)
	client := newGuardedClient(s, s.JSDownloadTimeout, true, 3)
	defer client.CloseIdleConnections()

	type disc struct {
		urls []string
		errs []string
	}
	discResults := make([]disc, len(domains))
	var eg errgroup.Group
	eg.SetLimit(s.JSMaxConcurrency)
	for i, domain := range domains {
		i, domain := i, domain
		eg.Go(func() error {
			r := resolved[domain]
			if r.IP == "" || r.Blocked {
				if r.Error != "" {
					discResults[i] = disc{errs: []string{r.Error}}
				}
				return nil
			}
			for _, base := range []string{"https://" + domain + "/", "http://" + domain + "/"} {
				_, body, status, _ := jsFetch(ctx, client, base, s.JSMaxFileBytes)
				if status == "ok" && body != nil {
					urls := ExtractJSURLs(string(body), base)
					if len(urls) > s.JSMaxFilesPerHost {
						urls = urls[:s.JSMaxFilesPerHost]
					}
					discResults[i] = disc{urls: urls}
					return nil
				}
			}
			discResults[i] = disc{errs: []string{domain + ": корень не отвечает"}}
			return nil
		})
	}
	_ = eg.Wait()

	var errors []string
	type job struct{ domain, url string }
	var jobs []job
	for i, domain := range domains {
		errors = append(errors, discResults[i].errs...)
		for _, u := range discResults[i].urls {
			if len(jobs) >= s.JSMaxTotalFiles {
				break
			}
			jobs = append(jobs, job{domain: domain, url: u})
		}
	}

	scanned := make([]ScannedFile, len(jobs))
	var eg2 errgroup.Group
	eg2.SetLimit(s.JSMaxConcurrency)
	for i, j := range jobs {
		i, j := i, j
		eg2.Go(func() error {
			ctype, body, status, errStr := jsFetch(ctx, client, j.url, s.JSMaxFileBytes)
			if status != "ok" || body == nil {
				scanned[i] = ScannedFile{URL: j.url, Hostname: j.domain, Status: status, Error: errStr, ContentType: ctype}
				return nil
			}
			text := string(body)
			sum := sha256.Sum256(body)
			size := int32(len(body))
			secrets, endpoints := MineJS(ctx, text, s.jsMineConfig())
			scanned[i] = ScannedFile{
				URL:         j.url,
				Hostname:    j.domain,
				Status:      "ok",
				SHA256:      hex.EncodeToString(sum[:]),
				SizeBytes:   &size,
				ContentType: ctype,
				Secrets:     secrets,
				Endpoints:   endpoints,
			}
			return nil
		})
	}
	_ = eg2.Wait()
	return scanned, errors
}

// jsEntryName — путь файла внутри архива: `<host>/<имя.js>`, коллизии — суффиксом
// (порт JsFarmService._entry_name).
func jsEntryName(rawURL string, used map[string]bool) string {
	host := "unknown"
	base := "index.js"
	if parsed, err := url.Parse(rawURL); err == nil {
		if parsed.Host != "" {
			host = parsed.Host
		}
		unescaped := parsed.Path
		if u, uerr := url.PathUnescape(parsed.Path); uerr == nil {
			unescaped = u
		}
		seg := path.Base(unescaped)
		if seg == "" || seg == "." || seg == "/" {
			seg = "index.js"
		}
		base = seg
	}
	base = strings.ReplaceAll(strings.ReplaceAll(base, "/", "_"), "\\", "_")
	if base == "" {
		base = "index.js"
	}
	name := host + "/" + base
	if !used[name] {
		used[name] = true
		return name
	}
	stem, dot, ext := rpartition(base, ".")
	if stem == "" {
		stem = base
	}
	for i := 2; ; i++ {
		variant := host + "/" + stem + "-" + strconv.Itoa(i) + dot + ext
		if !used[variant] {
			used[variant] = true
			return variant
		}
	}
}

func rpartition(s, sep string) (before, seperator, after string) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", "", s
	}
	return s[:i], sep, s[i+len(sep):]
}

// BuildJSArchive собирает zip из URL, докачивая их по требованию (порт build_archive).
// Имя архива: js-<host>.zip при host-скоупе, иначе js-project-<pid>.zip.
func BuildJSArchive(ctx context.Context, urls []string, hostScoped bool, projectID int32, s Settings) (string, []byte) {
	if len(urls) > s.JSMaxTotalFiles {
		urls = urls[:s.JSMaxTotalFiles]
	}
	archiveHost := ""
	if hostScoped {
		if parsed, err := url.Parse(urls[0]); err == nil {
			archiveHost = parsed.Host
		}
	}
	name := "js-project-" + strconv.Itoa(int(projectID)) + ".zip"
	if archiveHost != "" {
		name = "js-" + archiveHost + ".zip"
	}

	client := newGuardedClient(s, s.JSDownloadTimeout, true, 3)
	defer client.CloseIdleConnections()

	bodies := make([][]byte, len(urls))
	var eg errgroup.Group
	eg.SetLimit(s.JSMaxConcurrency)
	for i, u := range urls {
		i, u := i, u
		eg.Go(func() error {
			_, body, status, _ := jsFetch(ctx, client, u, s.JSMaxFileBytes)
			if status == "ok" {
				bodies[i] = body
			}
			return nil
		})
	}
	_ = eg.Wait()

	var buf bytes.Buffer
	used := map[string]bool{}
	wrote := 0
	zw := zip.NewWriter(&buf)
	for i, u := range urls {
		if bodies[i] == nil {
			continue
		}
		w, err := zw.Create(jsEntryName(u, used))
		if err != nil {
			continue
		}
		_, _ = w.Write(bodies[i])
		wrote++
	}
	if wrote == 0 {
		w, err := zw.Create("README.txt")
		if err == nil {
			_, _ = w.Write([]byte("Ни один JS-файл не удалось скачать повторно.\n"))
		}
	}
	_ = zw.Close()
	return name, buf.Bytes()
}
