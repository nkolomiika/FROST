package recon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Активный дир-фаззинг через ffuf (pure-Go бинарь, забандлен в recon-образ). Порт
// «dir_fuzz» стека для active/both режима стадии эндпоинтов. Как и остальные тулы:
// нет бинаря или словаря — стадия молча самопропускается (nil, ""). Словарь ВСЕГДА
// серверный путь (temp/bundled из MaterializeWordlist) — не пользовательское имя.

// ffufDefaultMatchCodes — коды статусов, считаемые «находкой» при дир-фаззинге.
// Не "all" — иначе в стейджинг попал бы каждый 404 (мусор); берём типовой набор
// «что-то есть по этому пути».
const ffufDefaultMatchCodes = "200,204,301,302,307,401,403,405,500"

// FfufDefaultMatchCodes отдаёт дефолтный набор match-кодов ffuf (для отображения
// команды в прогрессе без запуска бинаря).
func FfufDefaultMatchCodes() string { return ffufDefaultMatchCodes }

// FfufConfig — параметры одного дир-фаззинг-прогона.
type FfufConfig struct {
	RateLimit  int    // ffuf -rate (rps); 0 → не ограничиваем
	Threads    int    // ffuf -t (конкурентность); 0 → дефолт ffuf
	MatchCodes string // ffuf -mc; пусто → ffufDefaultMatchCodes
}

func (c FfufConfig) matchCodes() string {
	if c.MatchCodes == "" {
		return ffufDefaultMatchCodes
	}
	return c.MatchCodes
}

// FfufArgs собирает argv ffuf для фаззинга одного хоста. Вынесено отдельно — чтобы
// прогресс мог показать команду и покрыть тестом без запуска бинаря. wordlistPath
// и outPath — СЕРВЕРНЫЕ пути (temp/bundled), host гвардится вызывающим (safeHost).
func FfufArgs(host, wordlistPath, outPath string, cfg FfufConfig) []string {
	args := []string{
		"-w", wordlistPath,
		"-u", "https://" + host + "/FUZZ",
		"-mc", cfg.matchCodes(),
		"-of", "json",
		"-o", outPath,
		"-s",
	}
	if cfg.RateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(cfg.RateLimit))
	}
	if cfg.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Threads))
	}
	return args
}

// ffufOutput — форма JSON-отчёта ffuf (-of json): интересен только results[].url.
type ffufOutput struct {
	Results []struct {
		URL    string `json:"url"`
		Status int    `json:"status"`
	} `json:"results"`
}

// FfufDirFuzz гоняет ffuf по одному хосту и возвращает найденные URL (Source=ffuf).
// Нет бинаря / словаря / небезопасный host → пусто (не ошибка). Отмена — через ctx.
// Результат ffuf пишет в JSON-файл (-o); мы его читаем и парсим, затем удаляем.
func FfufDirFuzz(ctx context.Context, host, wordlistPath string, cfg FfufConfig, s Settings) ([]EndpointHit, string) {
	if !lookPathOK(s.FfufBin) || !WordlistExists(wordlistPath) || !safeHost(host) {
		return nil, ""
	}
	out, err := os.CreateTemp("", "frost-ffuf-*.json")
	if err != nil {
		return nil, "ffuf(" + host + "): " + errName(err)
	}
	outPath := out.Name()
	_ = out.Close()
	defer func() { _ = os.Remove(outPath) }()

	c, cancel := context.WithTimeout(ctx, s.EndpointsTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.FfufBin, FfufArgs(host, wordlistPath, outPath, cfg)...)
	if err := cmd.Run(); err != nil {
		// ffuf возвращает non-zero и при «ничего не найдено» на части версий —
		// отчёт всё равно читаем; ошибку не поднимаем, если файл распарсился.
		if hits := readFfufOutput(outPath); hits != nil {
			return hits, ""
		}
		return nil, "ffuf(" + host + "): " + errName(err)
	}
	return readFfufOutput(outPath), ""
}

// readFfufOutput читает и парсит JSON-отчёт ffuf в EndpointHit'ы (только http(s)-URL).
func readFfufOutput(path string) []EndpointHit {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var parsed ffufOutput
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	var hits []EndpointHit
	for _, r := range parsed.Results {
		u := strings.TrimSpace(r.URL)
		if u == "" {
			continue
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		hits = append(hits, EndpointHit{URL: u, Source: "ffuf"})
	}
	return hits
}
