package recon

import (
	"net/url"
	"regexp"
	"strings"
)

// Скан JS: секреты, пути, ссылки на .js. Чистые функции над строкой (порт
// app/farm/jsscan.py). Все regex — RE2-совместимы (без lookaround).

// Secret — находка секрета в JS (порт jsscan.Secret).
type Secret struct {
	Kind         string
	MatchPreview string
	Snippet      string
	Severity     string
}

type secretSpec struct {
	kind     string
	re       *regexp.Regexp
	severity string
	hasGroup bool // значение в группе 1 (generic), иначе всё совпадение
}

// _SECRET_SPECS: специфичные паттерны (AKIA/AIza/…) раньше общего generic_api_key —
// при дедупе по значению первое (специфичное) совпадение и остаётся.
var secretSpecs = []secretSpec{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "high", false},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), "high", false},
	{"github_pat", regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`), "high", false},
	{"github_fine_grained_pat", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{22,}\b`), "high", false},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`), "high", false},
	{"stripe_secret_key", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}\b`), "high", false},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), "high", false},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`), "medium", false},
	{"google_oauth_id", regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`), "medium", false},
	{"firebase_url", regexp.MustCompile(`\bhttps://[a-z0-9-]+\.firebaseio\.com\b`), "low", false},
	{"generic_api_key", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|token|client[_-]?secret|passwd|password|access[_-]?key)["'\s]*[:=]["'\s]*["']([0-9A-Za-z\-_]{16,})["']`), "medium", true},
}

var wsRe = regexp.MustCompile(`\s+`)

// Redact скрывает середину секрета: первые/последние 4 символа (порт redact).
func Redact(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 8 {
		if value == "" {
			return ""
		}
		return value[:1] + "***"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// snippet — контекст ±40 символов вокруг совпадения, одной строкой (порт _snippet).
func snippet(text string, start, end int) string {
	const width = 40
	left := start - width
	if left < 0 {
		left = 0
	}
	right := end + width
	if right > len(text) {
		right = len(text)
	}
	return strings.TrimSpace(wsRe.ReplaceAllString(text[left:right], " "))
}

// FindSecrets находит секреты с дедупом по (усечённому) redacted-значению (порт
// find_secrets). Полный секрет не сохраняется.
func FindSecrets(text string) []Secret {
	seen := map[string]bool{}
	var out []Secret
	for _, spec := range secretSpecs {
		for _, loc := range spec.re.FindAllStringSubmatchIndex(text, -1) {
			var raw string
			if spec.hasGroup && len(loc) >= 4 && loc[2] >= 0 {
				raw = text[loc[2]:loc[3]]
			} else {
				raw = text[loc[0]:loc[1]]
			}
			preview := truncate(Redact(raw), 255)
			if preview == "" || seen[preview] {
				continue
			}
			seen[preview] = true
			out = append(out, Secret{
				Kind:         spec.kind,
				MatchPreview: preview,
				Snippet:      truncate(snippet(text, loc[0], loc[1]), 255),
				Severity:     spec.severity,
			})
		}
	}
	return out
}

// ----------------------------------------------------------------------- paths

var pathRe = regexp.MustCompile("[\"'`]((?:https?:)?//[^\"'`\\s]{3,200}|/[a-zA-Z0-9_./\\-]{1,200}|[a-zA-Z0-9_\\-/]{1,100}/[a-zA-Z0-9_\\-/]{1,100})[\"'`]")

var pathNoiseExt = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".scss", ".less",
	".woff", ".woff2", ".ttf", ".eot", ".ico", ".map", ".mp4", ".webp",
}
var pathDenySubstr = []string{"node_modules", "webpack://", "data:", "text/", "application/", "image/"}

func isInterestingPath(path string) bool {
	low := strings.ToLower(path)
	for _, ext := range pathNoiseExt {
		if strings.HasSuffix(low, ext) {
			return false
		}
	}
	for _, s := range pathDenySubstr {
		if strings.Contains(low, s) {
			return false
		}
	}
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, "http") || strings.HasPrefix(path, "//") {
		return len(path) > 1
	}
	if !strings.Contains(path, "/") {
		return false
	}
	for _, c := range path {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// FindPaths извлекает пути/URL из JS, отсекая статику и мусор (порт find_paths).
func FindPaths(text string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range pathRe.FindAllStringSubmatch(text, -1) {
		path := strings.TrimSpace(m[1])
		if seen[path] || !isInterestingPath(path) {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// --------------------------------------------------------------- js-in-html

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'>\s]+)`)
var jsRefRe = regexp.MustCompile(`(?i)["'(]([^"'()\s]+?\.js(?:\?[^"'()\s]*)?)["')]`)

var jsDenyHosts = []string{
	"google-analytics.com", "googletagmanager.com", "gstatic.com",
	"facebook.net", "fbcdn.net", "doubleclick.net", "hotjar.com",
}

// ExtractJSURLs — абсолютные URL .js из HTML: <script src> + .js-ссылки, дедуп
// (порт extract_js_urls). Относительные резолвятся через baseURL.
func ExtractJSURLs(html, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, re := range []*regexp.Regexp{scriptSrcRe, jsRefRe} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			raw := strings.TrimSpace(m[1])
			if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "blob:") || strings.HasPrefix(raw, "javascript:") {
				continue
			}
			ref, perr := url.Parse(raw)
			if perr != nil {
				continue
			}
			abs := base.ResolveReference(ref)
			if abs.Scheme != "http" && abs.Scheme != "https" {
				continue
			}
			if abs.Host == "" {
				continue
			}
			pathOnly := strings.SplitN(strings.ToLower(abs.Path), "?", 2)[0]
			if !strings.HasSuffix(pathOnly, ".js") {
				continue
			}
			denied := false
			for _, deny := range jsDenyHosts {
				if strings.Contains(strings.ToLower(abs.Host), deny) {
					denied = true
					break
				}
			}
			if denied {
				continue
			}
			s := abs.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
