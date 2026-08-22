package recon

import (
	"context"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// newSearchClient — клиент для поисковых бэкендов (Google CSE, DuckDuckGo): цели —
// ФИКСИРОВАННЫЕ доверенные хосты (не пользовательский ввод), поэтому без SSRF-guard и
// с обычной проверкой TLS. Форсим IPv4: API-ключ Google CSE ограничивают по IPv4, а
// VPS по умолчанию уходит в googleapis по IPv6 — из-за чего ключ отвергается.
func newSearchClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp4", addr)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 16,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// LinkedIn-энумерация сотрудников компании БЕЗ логина в LinkedIn и без ключей:
// дёргаем поисковик (DuckDuckGo HTML — самый терпимый к скрейпу) по запросу
// `site:linkedin.com/in "Company"`, парсим ФИО из заголовков результатов и генерим
// вероятные корпоративные почты по частым форматам. Это фронт-энумератор для стадии
// поиска учёток: сгенерированные почты идут в breach-пробив, а сами найденные люди
// эмитятся как account-находки (source=linkedin). Подход search-engine (а не скрейп
// самого LinkedIn) не требует сессии и не банит аккаунт. Всё best-effort: блок
// поисковика / пусто — мягкий самопропуск, стадия не валится.

// LinkedInPerson — распознанный сотрудник (имя/фамилия + заголовок-подпись).
type LinkedInPerson struct {
	First    string
	Last     string
	Headline string
}

// ddgResultRe вытаскивает заголовки органических результатов DDG HTML.
var ddgResultRe = regexp.MustCompile(`(?s)class="result__a"[^>]*>(.*?)</a>`)

// tagRe вырезает вложенные теги (<b> подсветка запроса и т.п.) из заголовка.
var tagRe = regexp.MustCompile(`<[^>]+>`)

// linkedinSearchURL — DDG HTML endpoint с пагинацией через offset s.
func linkedinSearchURL(company string, offset int) string {
	q := `site:linkedin.com/in "` + company + `"`
	v := url.Values{"q": {q}}
	if offset > 0 {
		v.Set("s", strconv.Itoa(offset))
	}
	return "https://html.duckduckgo.com/html/?" + v.Encode()
}

// EnumerateLinkedIn ищет сотрудников компании через поисковик и возвращает уникальных
// людей (дедуп по имени+фамилии) + мягкую пометку при проблеме. Пусто — не ошибка.
func EnumerateLinkedIn(ctx context.Context, company string, s Settings) ([]LinkedInPerson, string) {
	company = strings.TrimSpace(company)
	if company == "" {
		return nil, ""
	}
	timeout := s.LinkedInTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	client := newSearchClient(timeout)
	defer client.CloseIdleConnections()

	maxResults := s.LinkedInMaxResults
	if maxResults <= 0 {
		maxResults = 150
	}

	// Google CSE (если заданы ключ+cx) — надёжный JSON-бэкенд, датацентр-IP не банит.
	// Иначе — скрейп DDG (best-effort, часто блокируется с серверных IP).
	var pages []string
	viaGoogle := strings.TrimSpace(s.GoogleCSEKey) != "" && strings.TrimSpace(s.GoogleCSECx) != ""
	if viaGoogle {
		pages = []string{"1", "11", "21"} // start-offset'ы CSE (10 на страницу)
	} else {
		pages = []string{"0", "30", "60"} // s-offset'ы DDG HTML
	}

	seen := map[string]struct{}{}
	var people []LinkedInPerson
	var lastNote string
	for _, pg := range pages {
		if len(people) >= maxResults {
			break
		}
		if ctx.Err() != nil {
			break
		}
		var found []LinkedInPerson
		var note string
		if viaGoogle {
			body, n := linkedinFetch(ctx, client, googleCSEURL(s.GoogleCSEKey, s.GoogleCSECx, company, pg))
			if n != "" {
				note = n
			} else {
				found, note = parseGoogleCSE(body)
			}
		} else {
			off, _ := strconv.Atoi(pg)
			body, n := linkedinFetch(ctx, client, linkedinSearchURL(company, off))
			if n != "" {
				note = n
			} else {
				found = parseLinkedInResults(body)
			}
		}
		if note != "" {
			lastNote = note
			break
		}
		if len(found) == 0 {
			break // пусто — дальше листать смысла нет
		}
		for _, p := range found {
			key := strings.ToLower(p.First + "\x00" + p.Last)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			people = append(people, p)
			if len(people) >= maxResults {
				break
			}
		}
	}
	if len(people) == 0 && lastNote != "" {
		return nil, "linkedin(" + company + "): " + lastNote
	}
	return people, ""
}

// emailRe — грубый матч e-mail в тексте (title/snippet результатов).
var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// harvestMaxEmails — потолок собранных почт (защита от раздувания breach-пробива).
const harvestMaxEmails = 100

// HarvestEmailsCSE ищет через Google CSE РЕАЛЬНЫЕ почты доменов, засветившиеся в вебе
// (GitHub, пасты, доки, форумы — «весь веб»). Не угадывает, а находит уже опубликованные.
// Требует настроенный CSE (ключ+cx) — иначе пусто. Возвращает уникальные почты + пометку.
func HarvestEmailsCSE(ctx context.Context, domains []string, s Settings) ([]string, string) {
	if strings.TrimSpace(s.GoogleCSEKey) == "" || strings.TrimSpace(s.GoogleCSECx) == "" {
		return nil, ""
	}
	timeout := s.LinkedInTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	client := newSearchClient(timeout)
	defer client.CloseIdleConnections()

	seen := map[string]struct{}{}
	var out []string
	var lastNote string
	for _, d := range domains {
		dl := strings.ToLower(strings.TrimSpace(d))
		if dl == "" {
			continue
		}
		for _, start := range []string{"1", "11"} {
			if len(out) >= harvestMaxEmails || ctx.Err() != nil {
				break
			}
			body, note := linkedinFetch(ctx, client, googleCSEEmailURL(s.GoogleCSEKey, s.GoogleCSECx, dl, start))
			if note != "" {
				lastNote = note
				break
			}
			found, perr := extractEmailsFromCSE(body, dl)
			if perr != "" {
				lastNote = perr
				break
			}
			if len(found) == 0 {
				break
			}
			for _, e := range found {
				if _, ok := seen[e]; ok {
					continue
				}
				seen[e] = struct{}{}
				out = append(out, e)
				if len(out) >= harvestMaxEmails {
					break
				}
			}
		}
	}
	if len(out) == 0 && lastNote != "" {
		return nil, "email-harvest: " + lastNote
	}
	return out, ""
}

// googleCSEEmailURL — CSE-запрос на почты домена: ищем страницы, где встречается
// "@domain" (пасты/GitHub/доки), из title+snippet потом вытащим сами адреса.
func googleCSEEmailURL(key, cx, domain, start string) string {
	v := url.Values{
		"key": {key},
		"cx":  {cx},
		"q":   {`"@` + domain + `"`},
		"num": {"10"},
	}
	if start != "" && start != "1" {
		v.Set("start", start)
	}
	return "https://www.googleapis.com/customsearch/v1?" + v.Encode()
}

// extractEmailsFromCSE достаёт из JSON CSE все почты домена (из title+snippet).
func extractEmailsFromCSE(body, domain string) ([]string, string) {
	var resp struct {
		Items []struct {
			Title   string `json:"title"`
			Snippet string `json:"snippet"`
		} `json:"items"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, "cse_parse"
	}
	if resp.Error.Message != "" {
		return nil, "cse: " + resp.Error.Message
	}
	suffix := "@" + strings.ToLower(domain)
	seen := map[string]struct{}{}
	var out []string
	for _, it := range resp.Items {
		text := html.UnescapeString(it.Title + " " + it.Snippet)
		for _, m := range emailRe.FindAllString(text, -1) {
			el := strings.ToLower(m)
			if !strings.HasSuffix(el, suffix) {
				continue
			}
			if _, ok := seen[el]; ok {
				continue
			}
			seen[el] = struct{}{}
			out = append(out, el)
		}
	}
	return out, ""
}

// googleCSEURL — Custom Search JSON API: site:linkedin.com/in "Company", 10/страница.
func googleCSEURL(key, cx, company, start string) string {
	v := url.Values{
		"key": {key},
		"cx":  {cx},
		"q":   {`site:linkedin.com/in "` + company + `"`},
		"num": {"10"},
	}
	if start != "" && start != "1" {
		v.Set("start", start)
	}
	return "https://www.googleapis.com/customsearch/v1?" + v.Encode()
}

// parseGoogleCSE разбирает JSON-ответ CSE в людей. Ошибка API (квота/ключ) → note.
func parseGoogleCSE(body string) ([]LinkedInPerson, string) {
	var resp struct {
		Items []struct {
			Title string `json:"title"`
		} `json:"items"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, "cse_parse"
	}
	if resp.Error.Message != "" {
		return nil, "cse: " + resp.Error.Message
	}
	var out []LinkedInPerson
	for _, it := range resp.Items {
		if p, ok := parseLinkedInName(html.UnescapeString(it.Title)); ok {
			out = append(out, p)
		}
	}
	return out, ""
}

func linkedinFetch(ctx context.Context, client *http.Client, target string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", errName(err)
	}
	// Браузерный UA — DDG HTML отдаёт органику охотнее, чем «голому» клиенту.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return "", errName(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", "http_" + strconv.Itoa(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20)) // 4MiB потолок страницы
	if err != nil {
		return "", errName(err)
	}
	return string(data), ""
}

// parseLinkedInResults разбирает заголовки результатов в людей. Заголовок профиля
// LinkedIn обычно вида «First Last - Headline - Company | LinkedIn».
func parseLinkedInResults(body string) []LinkedInPerson {
	var out []LinkedInPerson
	for _, m := range ddgResultRe.FindAllStringSubmatch(body, -1) {
		title := html.UnescapeString(tagRe.ReplaceAllString(m[1], ""))
		title = strings.TrimSpace(title)
		if title == "" {
			continue
		}
		if p, ok := parseLinkedInName(title); ok {
			out = append(out, p)
		}
	}
	return out
}

// nameSepRe режет ФИО-часть от подписи (первый из « - », « – », « | », «, », « — »).
var nameSepRe = regexp.MustCompile(`\s[-–—|]\s|,\s`)

// nameTokenRe — валидный токен имени: только буквы, дефис, апостроф (без цифр/мусора).
var nameTokenRe = regexp.MustCompile(`^[\p{L}][\p{L}'’-]*$`)

// parseLinkedInName извлекает first/last из заголовка результата. Берём часть до
// первого разделителя как ФИО, first=первый токен, last=последний. Отсекаем мусор.
func parseLinkedInName(title string) (LinkedInPerson, bool) {
	headline := ""
	namePart := title
	if loc := nameSepRe.FindStringIndex(title); loc != nil {
		namePart = title[:loc[0]]
		headline = strings.TrimSpace(title[loc[1]:])
	}
	namePart = strings.TrimSpace(namePart)
	if namePart == "" {
		return LinkedInPerson{}, false
	}
	fields := strings.Fields(namePart)
	// Нужны минимум 2 валидных токена; «LinkedIn» и подобное не считаем именем.
	var toks []string
	for _, f := range fields {
		if strings.EqualFold(f, "linkedin") {
			continue
		}
		if !nameTokenRe.MatchString(f) {
			return LinkedInPerson{}, false // цифры/мусор в имени → это не профиль
		}
		toks = append(toks, f)
	}
	if len(toks) < 2 {
		return LinkedInPerson{}, false
	}
	first := toks[0]
	last := toks[len(toks)-1]
	return LinkedInPerson{First: first, Last: last, Headline: headline}, true
}

// defaultEmailFormats — самые частые корпоративные форматы (плейсхолдеры {first},
// {last}, {f}, {l}). Держим набор компактным, чтобы не раздувать список пробива.
var defaultEmailFormats = []string{"{first}.{last}", "{f}{last}", "{first}{last}"}

// GenerateEmails строит вероятные почты: люди × форматы × домены, нормализуя и
// дедупя, с общим потолком cap (0 → дефолт 150). Пустые домены → пусто.
func GenerateEmails(people []LinkedInPerson, domains []string, cap int) []string {
	if cap <= 0 {
		cap = 150
	}
	var doms []string
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			doms = append(doms, d)
		}
	}
	if len(doms) == 0 || len(people) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, p := range people {
		first := normalizeNamePart(p.First)
		last := normalizeNamePart(p.Last)
		if first == "" || last == "" {
			continue
		}
		local := map[string]string{
			"{first}": first, "{last}": last,
			"{f}": first[:1], "{l}": last[:1],
		}
		for _, fmtStr := range defaultEmailFormats {
			lp := fmtStr
			for k, v := range local {
				lp = strings.ReplaceAll(lp, k, v)
			}
			for _, d := range doms {
				email := lp + "@" + d
				if _, ok := seen[email]; ok {
					continue
				}
				seen[email] = struct{}{}
				out = append(out, email)
				if len(out) >= cap {
					return out
				}
			}
		}
	}
	return out
}

// normalizeNamePart приводит токен имени к ascii-latin lower [a-z] (для локальной
// части почты): убираем всё, кроме латинских букв. Нелатиница схлопнется в пусто —
// такой человек пропускается при генерации (но остаётся account-находкой).
func normalizeNamePart(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(s)) {
		if r >= 'a' && r <= 'z' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
