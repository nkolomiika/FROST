package recon

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// Стадия эндпоинтов полного прогона фермы: сбор URL по живым хостам тремя
// инструментами — katana (активный краул), gau и waybackurls (пассивные архивы).
// Каждый — статический Go-бинарь (забандлен в recon-образ). Отсутствие бинаря —
// НЕ ошибка: инструмент молча самопропускается (как DNSXBrute), стадия деградирует.

// EndpointHit — один найденный URL стадии эндпоинтов (Method обычно пуст — URL без
// метода; Source — инструмент-источник: katana|gau|waybackurls).
type EndpointHit struct {
	URL    string
	Method string
	Source string
}

// EndpointToolConfig — высокоуровневые ручки прогона для инструментов эндпоинтов.
type EndpointToolConfig struct {
	CrawlDepth int // глубина краула katana (-d)
	RateLimit  int // rps (katana -rl / ffuf -rate)
	// ffuf (активный дир-фаззинг): СЕРВЕРНЫЙ путь словаря (temp/bundled) и конкурентность.
	// Пусто → ffuf самопропускается (см. FfufDirFuzz). Путь всегда серверный, не имя файла.
	FfufWordlist string
	Threads      int // ffuf -t
}

// KatanaArgs собирает аргументы katana для краула одного хоста. Вынесено отдельно,
// чтобы прогресс мог показать точную команду и покрыть тестом без запуска бинаря.
func KatanaArgs(host string, cfg EndpointToolConfig) []string {
	depth := cfg.CrawlDepth
	if depth < 1 {
		depth = 1
	}
	args := []string{"-u", "https://" + host, "-d", strconv.Itoa(depth), "-jc", "-silent", "-nc"}
	if cfg.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateLimit))
	}
	return args
}

// streamHits гоняет cmd и стримит его stdout построчно в EndpointHit'ы, не буферизуя
// весь вывод в памяти: gau --subs / waybackurls на живом домене легко выдают сотни
// МБ (100k–1M+ строк), а cmd.Output() держал бы это всё в RAM разом (× конкурентность
// хостов → OOM). maxLines>0 — потолок на хост: набрали — убиваем процесс и выходим
// (поток архивных URL всё равно почти весь шум). label — для текста ошибки.
func streamHits(cmd *exec.Cmd, source, label string, maxLines int) ([]EndpointHit, string) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, label + ": " + errName(err)
	}
	if err := cmd.Start(); err != nil {
		return nil, label + ": " + errName(err)
	}
	var hits []EndpointHit
	killed := false
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		hits = append(hits, EndpointHit{URL: line, Source: source})
		if maxLines > 0 && len(hits) >= maxLines {
			killed = true
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			break
		}
	}
	werr := cmd.Wait()
	// Убили сами (достигли потолка) или что-то нашли — не считаем ошибкой.
	if werr != nil && !killed && len(hits) == 0 {
		return nil, label + ": " + errName(werr)
	}
	return hits, ""
}

// KatanaURLs гоняет katana-краул по хосту и возвращает найденные URL. Нет бинаря →
// пусто (не ошибка). Отмена — через ctx (per-step cancel рвёт процесс).
func KatanaURLs(ctx context.Context, host string, cfg EndpointToolConfig, s Settings) ([]EndpointHit, string) {
	// safeHost: host идёт в argv (-u https://host) — значение с ведущим '-' бинарь
	// принял бы за флаг; такие хосты пропускаем (не ошибка).
	if !lookPathOK(s.KatanaBin) || !safeHost(host) {
		return nil, ""
	}
	c, cancel := context.WithTimeout(ctx, s.EndpointsTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.KatanaBin, KatanaArgs(host, cfg)...)
	return streamHits(cmd, "katana", "katana("+host+")", s.EndpointsMaxPerHost)
}

// GauURLs гоняет gau (архивные URL) по хосту (домен через stdin) и возвращает URL.
// Нет бинаря → пусто (не ошибка).
func GauURLs(ctx context.Context, host string, s Settings) ([]EndpointHit, string) {
	if !lookPathOK(s.GauBin) {
		return nil, ""
	}
	c, cancel := context.WithTimeout(ctx, s.EndpointsTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.GauBin, "--subs")
	cmd.Stdin = strings.NewReader(host + "\n")
	return streamHits(cmd, "gau", "gau("+host+")", s.EndpointsMaxPerHost)
}

// WaybackURLs гоняет waybackurls (архив Wayback) по хосту (домен через stdin) и
// возвращает URL. Нет бинаря → пусто (не ошибка).
func WaybackURLs(ctx context.Context, host string, s Settings) ([]EndpointHit, string) {
	if !lookPathOK(s.WaybackurlsBin) {
		return nil, ""
	}
	c, cancel := context.WithTimeout(ctx, s.EndpointsTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.WaybackurlsBin)
	cmd.Stdin = strings.NewReader(host + "\n")
	return streamHits(cmd, "waybackurls", "waybackurls("+host+")", s.EndpointsMaxPerHost)
}

// hitsFromLines разбирает построчный вывод инструмента в EndpointHit'ы: только
// http(s)-URL, пустые/мусорные строки отбрасываются. Дедуп — на стороне вызывающего.
func hitsFromLines(out, source string) []EndpointHit {
	var hits []EndpointHit
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		hits = append(hits, EndpointHit{URL: line, Source: source})
	}
	return hits
}
