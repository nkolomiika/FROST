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
	"os"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// Ферма JS: discover .js на доменах, download (стримом на диск) и греп секретов/путей.
// Порт app/farm/js.py фаз discover+download+archive (без БД).

// Скан файлов ЛЮБОГО размера: большие бандлы не пропускаем (раньше > JSMaxFileBytes
// давали status=too_large и не сканились). Чтобы это не съедало RAM, скачиваем
// стримом в temp-файл на диске (константный буфер io.Copy), а чтение файла в память
// под MineJS гейтим общим байт-бюджетом (semaphore.Weighted) — пик RAM ограничен
// бюджетом независимо от конкурентности и размера конкретного файла.

const (
	// Кап на скачивание корневой HTML-страницы при discover (нужна лишь для
	// извлечения ссылок на .js) — держим маленьким, чтобы discover был дешёвым.
	jsRootFetchCap = 16 << 20 // 16 MiB
	// Кап на файл при сборке экспортного zip-архива (BuildJSArchive держит все тела
	// в памяти сразу) — ограничиваем, чтобы экспорт не ушёл в OOM. Скан (выше) капа
	// не имеет; это только про удобную выгрузку архива.
	jsArchiveFileCap = 25 << 20 // 25 MiB
	// Дефолт байт-бюджета скана, если Settings.JSMaxInflightBytes не задан.
	jsDefaultInflightBytes = 256 << 20 // 256 MiB
)

// ScannedFile — итог скана одного .js (порт js.ScannedFile).
type ScannedFile struct {
	URL         string
	Hostname    string
	Status      string // ok | failed | too_large (too_large только при заданном потолке JSMaxFileBytes>0)
	Error       string
	SHA256      string
	SizeBytes   *int32
	ContentType string
	Secrets     []Secret
	Endpoints   []string
}

// jsFetch — GET с капом размера В ПАМЯТЬ (для мелких ответов: корневой HTML при
// discover, тела при экспорте архива). status: ok | too_large | failed. maxBytes<=0 →
// без потолка. Для скана используем jsFetchToTemp (стрим на диск), не эту функцию.
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
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, int64(maxBytes)+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return ctype, nil, "failed", errName(err)
	}
	if maxBytes > 0 && len(data) > maxBytes {
		return ctype, nil, "too_large", ""
	}
	return ctype, data, "ok", ""
}

// jsFetchToTemp стримит GET в temp-файл на диске (постоянный RAM ~ буфер io.Copy),
// файлы любого размера. maxBytes<=0 → без потолка (сканим всё); иначе потолок и
// too_large при превышении. Вызывающий ОБЯЗАН os.Remove(filePath) при filePath!="".
func jsFetchToTemp(ctx context.Context, client *http.Client, target string, maxBytes int) (ctype, filePath string, size int64, status, errStr string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", "", 0, "failed", errName(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, "failed", errName(err)
	}
	defer resp.Body.Close()
	ctype = resp.Header.Get("Content-Type")
	if resp.StatusCode >= 400 {
		return ctype, "", 0, "failed", "http_" + strconv.Itoa(resp.StatusCode)
	}
	tmp, err := os.CreateTemp("", "frostjs-*.js")
	if err != nil {
		return ctype, "", 0, "failed", errName(err)
	}
	var reader io.Reader = resp.Body
	if maxBytes > 0 {
		reader = io.LimitReader(resp.Body, int64(maxBytes)+1)
	}
	n, cerr := io.Copy(tmp, reader)
	_ = tmp.Close()
	if cerr != nil {
		_ = os.Remove(tmp.Name())
		return ctype, "", 0, "failed", errName(cerr)
	}
	if maxBytes > 0 && n > int64(maxBytes) {
		_ = os.Remove(tmp.Name())
		return ctype, "", 0, "too_large", ""
	}
	return ctype, tmp.Name(), n, "ok", ""
}

// scanBudget возвращает байт-бюджет скана и его вместимость. Если shared передан
// (общий на весь прогон фермы — чтобы конкурентные хосты не перемножали пик RAM),
// используем его; иначе создаём локальный на этот вызов.
func scanBudget(s Settings, shared ...*semaphore.Weighted) (*semaphore.Weighted, int64) {
	cap := int64(s.JSMaxInflightBytes)
	if cap < 1 {
		cap = jsDefaultInflightBytes
	}
	if len(shared) > 0 && shared[0] != nil {
		return shared[0], cap
	}
	return semaphore.NewWeighted(cap), cap
}

// DiscoverAndScan — фазы 2–3 без БД: находит .js по доменам, качает (стримом на диск)
// и грепает (порт JsFarmService._discover_and_scan). shared — необязательный общий
// байт-бюджет скана (см. scanBudget); nil/пусто → локальный.
func DiscoverAndScan(ctx context.Context, domains []string, s Settings, shared ...*semaphore.Weighted) ([]ScannedFile, []string) {
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
				_, body, status, _ := jsFetch(ctx, client, base, jsRootFetchCap)
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

	budget, budgetCap := scanBudget(s, shared...)
	scanned := make([]ScannedFile, len(jobs))
	var eg2 errgroup.Group
	eg2.SetLimit(s.JSMaxConcurrency)
	for i, j := range jobs {
		i, j := i, j
		eg2.Go(func() error {
			ctype, fp, size, status, errStr := jsFetchToTemp(ctx, client, j.url, s.JSMaxFileBytes)
			if status != "ok" || fp == "" {
				scanned[i] = ScannedFile{URL: j.url, Hostname: j.domain, Status: status, Error: errStr, ContentType: ctype}
				return nil
			}
			defer os.Remove(fp)
			// Бюджет RAM держим на время чтения файла + MineJS. Вес = размер файла,
			// но не больше всей вместимости бюджета — файл крупнее бюджета сканим в
			// одиночку (Acquire не должен просить больше total, иначе навсегда виснет).
			w := size
			if w > budgetCap {
				w = budgetCap
			}
			if w < 1 {
				w = 1
			}
			if err := budget.Acquire(ctx, w); err != nil {
				scanned[i] = ScannedFile{URL: j.url, Hostname: j.domain, Status: "failed", Error: errName(err), ContentType: ctype}
				return nil
			}
			body, rerr := os.ReadFile(fp)
			if rerr != nil {
				budget.Release(w)
				scanned[i] = ScannedFile{URL: j.url, Hostname: j.domain, Status: "failed", Error: errName(rerr), ContentType: ctype}
				return nil
			}
			text := string(body)
			sum := sha256.Sum256(body)
			sz := int32(len(body))
			secrets, endpoints := MineJS(ctx, text, s.jsMineConfig())
			budget.Release(w)
			scanned[i] = ScannedFile{
				URL:         j.url,
				Hostname:    j.domain,
				Status:      "ok",
				SHA256:      hex.EncodeToString(sum[:]),
				SizeBytes:   &sz,
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
// Имя архива: js-<host>.zip при host-скоупе, иначе js-project-<pid>.zip. Тела держатся
// в памяти сразу, поэтому здесь кап на файл (jsArchiveFileCap) — только для экспорта.
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
			_, body, status, _ := jsFetch(ctx, client, u, jsArchiveFileCap)
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
