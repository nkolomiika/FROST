package recon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"
)

// JS-майнинг внешними инструментами: jsluice (секреты + эндпоинты) и trufflehog
// (verified-секреты). Заметно точнее встроенного regex-сканера. Если бинарей нет
// (dev-окружение), откатываемся на FindSecrets/FindPaths — ферма работает всегда.

// JSMineConfig — настройки внешнего JS-майнинга.
type JSMineConfig struct {
	Enabled          bool
	JsluiceBin       string
	TrufflehogBin    string
	TrufflehogConfig string // --config (кастомные детекторы: UUID)
	Timeout          time.Duration
}

func ready(enabled bool, bin string) bool {
	if !enabled || bin == "" {
		return false
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

// MineJS извлекает секреты и эндпоинты из содержимого одного JS-файла. Источники
// объединяются для максимального покрытия: встроенный regex ВСЕГДА + jsluice и
// trufflehog, когда их бинари доступны. Инструменты используются независимо друг
// от друга; при их отсутствии остаётся только regex.
func MineJS(ctx context.Context, text string, cfg JSMineConfig) (secrets []Secret, endpoints []string) {
	// Эндпоинты — regex-эвристика всегда (полные пути, дружелюбны к дедупу).
	endpoints = FindPaths(text)

	// Встроенный regex-сканер работает ВСЕГДА (полные значения, redact=false) —
	// он ловит app-специфичные секреты (JWT, generic api_key/token/password),
	// которых нет в детекторах trufflehog. Инструменты (когда доступны) добавляют
	// провайдерские verified-секреты сверху. Объединение = максимум покрытия.
	secrets = scanSecrets(text, false)

	jsReady := ready(cfg.Enabled, cfg.JsluiceBin)
	thReady := ready(cfg.Enabled, cfg.TrufflehogBin)
	if !jsReady && !thReady {
		return dedupSecrets(secrets), endpoints
	}

	f, err := os.CreateTemp("", "frostjs-*.js")
	if err != nil {
		return secrets, endpoints
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(text); err != nil {
		_ = f.Close()
		return secrets, endpoints
	}
	_ = f.Close()

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if jsReady {
		secrets = append(secrets, jsluiceSecrets(c, cfg.JsluiceBin, path)...)
		endpoints = append(endpoints, jsluiceURLs(c, cfg.JsluiceBin, path)...)
	}
	if thReady {
		secrets = append(secrets, trufflehogSecrets(c, cfg.TrufflehogBin, cfg.TrufflehogConfig, path)...)
	}
	return dedupSecrets(secrets), dedupStrings(endpoints)
}

// ── jsluice ──

func jsluiceSecrets(ctx context.Context, bin, path string) []Secret {
	out, err := exec.CommandContext(ctx, bin, "secrets", path).Output()
	if err != nil {
		return nil
	}
	var res []Secret
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m struct {
			Kind     string         `json:"kind"`
			Data     map[string]any `json:"data"`
			Severity string         `json:"severity"`
			Context  map[string]any `json:"context"`
		}
		if json.Unmarshal([]byte(line), &m) != nil {
			continue
		}
		val := joinValues(m.Data)
		if val == "" {
			continue
		}
		res = append(res, Secret{
			Kind:         "jsluice:" + m.Kind,
			MatchPreview: truncate(val, 255),
			Snippet:      truncate(compactJSON(m.Context), 255),
			Severity:     normSecretSeverity(m.Severity),
		})
	}
	return res
}

func jsluiceURLs(ctx context.Context, bin, path string) []string {
	out, err := exec.CommandContext(ctx, bin, "urls", path).Output()
	if err != nil {
		return nil
	}
	var res []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m struct {
			URL string `json:"url"`
		}
		if json.Unmarshal([]byte(line), &m) != nil || m.URL == "" {
			continue
		}
		res = append(res, m.URL)
	}
	return res
}

// ── trufflehog ──

func trufflehogSecrets(ctx context.Context, bin, configPath, path string) []Secret {
	// --no-update: не ходить за обновлениями; верификация включена — trufflehog
	// подтверждает креды у провайдера (verified → критично). --config: кастомные
	// детекторы (UUID) — тот же yaml, что и в github-скане; только если файл есть.
	args := []string{"filesystem", path, "--json", "--no-update"}
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			args = append(args, "--config="+configPath)
		}
	}
	out, err := exec.CommandContext(ctx, bin, args...).Output()
	if err != nil {
		// trufflehog возвращает ненулевой код, когда нашёл секреты, — вывод всё равно валиден.
		if len(out) == 0 {
			return nil
		}
	}
	var res []Secret
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var m struct {
			DetectorName string `json:"DetectorName"`
			Verified     bool   `json:"Verified"`
			Raw          string `json:"Raw"`
		}
		if json.Unmarshal([]byte(line), &m) != nil || m.DetectorName == "" || m.Raw == "" {
			continue
		}
		kind := "trufflehog:" + m.DetectorName
		sev := "high"
		snip := "unverified"
		if m.Verified {
			kind += " ✓verified"
			sev = "critical"
			snip = "verified via provider API"
		}
		res = append(res, Secret{Kind: kind, MatchPreview: truncate(m.Raw, 255), Snippet: snip, Severity: sev})
	}
	return res
}

// ── helpers ──

func joinValues(m map[string]any) string {
	parts := make([]string, 0, len(m))
	for _, v := range m {
		if s, ok := v.(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

func compactJSON(m map[string]any) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

func normSecretSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "medium"
	}
}

func dedupSecrets(in []Secret) []Secret {
	seen := map[string]bool{}
	out := make([]Secret, 0, len(in))
	for _, s := range in {
		if s.MatchPreview == "" || seen[s.MatchPreview] {
			continue
		}
		seen[s.MatchPreview] = true
		out = append(out, s)
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
