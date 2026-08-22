package recon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Breach-источники утечек по домену/почте (hibp/dehashed/intelx/leakcheck/snusbase/
// proxynova). Наличие workspace-ключа решает, активен ли источник: без ключа он
// самопропускается (Enabled==false) и НЕ роняет прогон — как dnsx-брут без словаря.
// Все сетевые вызовы идут через HTTPDoer-сим, поэтому тесты подсовывают мок round-trip
// и реальная сеть в тестах не дёргается.
//
// БЕЗОПАСНОСТЬ: пользовательские домены/почты уходят как query/JSON-параметры
// (url.Values / url.PathEscape), НИКОГДА как аргументы процесса. Шелла тут нет вовсе.

// HTTPDoer — сим HTTP round-trip (его реализует *http.Client). nil в конфиге →
// дефолтный клиент с таймаутом.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// BreachHTTPConfig — общий сетевой конфиг breach-источников.
type BreachHTTPConfig struct {
	Doer      HTTPDoer
	Timeout   time.Duration
	UserAgent string
}

func (c BreachHTTPConfig) doer() HTTPDoer {
	if c.Doer != nil {
		return c.Doer
	}
	return &http.Client{Timeout: c.timeout()}
}

func (c BreachHTTPConfig) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 15 * time.Second
	}
	return c.Timeout
}

func (c BreachHTTPConfig) ua() string {
	if c.UserAgent == "" {
		return "frost-recon"
	}
	return c.UserAgent
}

// BreachKeys — workspace-ключи breach-источников (пустая строка = не сконфигурирован).
type BreachKeys struct {
	HIBP      string
	Dehashed  string
	IntelX    string
	LeakCheck string
	Snusbase  string
	ProxyNova string
}

// Виды цели поиска.
const (
	BreachTargetDomain = "domain"
	BreachTargetEmail  = "email"
)

// BreachTarget — цель поиска: домен или почта.
type BreachTarget struct {
	Kind  string // BreachTargetDomain | BreachTargetEmail
	Value string
}

// BreachLeak — одна находка breach-источника (source-agnostic; кладётся в recon_leaks).
type BreachLeak struct {
	Source  string
	Kind    string // "credential" (есть пароль/хеш) | "account" (только факт присутствия)
	Subject string // почта/домен, к которому относится находка
	Value   string // утёкший пароль/хеш, если источник его отдаёт
	Detail  map[string]any
}

// BreachSource — источник breach-данных за единым интерфейсом. Enabled(keys) решает
// активность по наличию ключа; Search гоняет поиск по одной цели.
type BreachSource interface {
	Name() string
	Enabled(keys BreachKeys) bool
	Search(ctx context.Context, target BreachTarget) ([]BreachLeak, error)
}

// AllBreachSources возвращает ВСЕ известные источники (каждый со своим ключом и общим
// HTTP-симом). Приоритетов нет — реестр прогона фильтрует их по Enabled(keys) и гоняет
// все сконфигурированные.
func AllBreachSources(keys BreachKeys, cfg BreachHTTPConfig) []BreachSource {
	// ProxyNova COMB — БЕСПЛАТНЫЙ публичный API (ключ не нужен): активен всегда.
	// Остальные источники платные и самопропускаются, пока не задан ключ (позже
	// ключи зашьём в конфиг). Это даёт рабочий бесплатный domain/email-пробив «из
	// коробки», не завися от интеграций.
	proxynova := newThinBreachSource("proxynova", "", cfg, func(_ string, t BreachTarget) (*http.Request, error) {
		q := url.Values{"query": {t.Value}}
		return http.NewRequest(http.MethodGet, "https://api.proxynova.com/comb?"+q.Encode(), nil)
	})
	proxynova.keyless = true

	return []BreachSource{
		&hibpSource{key: keys.HIBP, cfg: cfg},
		&dehashedSource{key: keys.Dehashed, cfg: cfg},
		&intelxSource{key: keys.IntelX, cfg: cfg},
		&leakcheckSource{cfg: cfg}, // публичный keyless API (email + domain)
		newThinBreachSource("snusbase", keys.Snusbase, cfg, func(key string, t BreachTarget) (*http.Request, error) {
			q := url.Values{"term": {t.Value}, "type": {snusbaseType(t.Kind)}}
			req, err := http.NewRequest(http.MethodGet, "https://api.snusbase.com/data/search?"+q.Encode(), nil)
			if err == nil {
				req.Header.Set("Auth", key)
			}
			return req, err
		}),
		proxynova,
	}
}

func leakcheckType(kind string) string {
	if kind == BreachTargetDomain {
		return "domain"
	}
	return "email"
}

func snusbaseType(kind string) string {
	if kind == BreachTargetDomain {
		return "domain"
	}
	return "email"
}

// ─────────────────────────── общий HTTP-путь ───────────────────────────

// breachDo выполняет запрос через сим, отсеивает 404 (нет данных → пусто) и
// возвращает тело при 2xx. Прочие коды → ошибка (мягкая для прогона).
func breachDo(ctx context.Context, cfg BreachHTTPConfig, source string, req *http.Request) ([]byte, bool, error) {
	c, cancel := context.WithTimeout(ctx, cfg.timeout())
	defer cancel()
	req = req.WithContext(c)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", cfg.ua())
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := cfg.doer().Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", source, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil // нет находок (hibp отдаёт 404 на «чистую» почту)
	}
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("%s: http_%d", source, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", source, err)
	}
	return body, true, nil
}

// ─────────────────────────── HIBP (реальный) ───────────────────────────

// hibpSource — HaveIBeenPwned: поиск брешей по почте (breachedaccount) или домену
// (breaches?Domain=). Ключ уходит в заголовок hibp-api-key.
type hibpSource struct {
	key string
	cfg BreachHTTPConfig
}

func (h *hibpSource) Name() string { return "hibp" }

func (h *hibpSource) Enabled(keys BreachKeys) bool { return strings.TrimSpace(keys.HIBP) != "" }

func (h *hibpSource) Search(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	if strings.TrimSpace(h.key) == "" {
		return nil, nil
	}
	switch t.Kind {
	case BreachTargetEmail:
		return h.searchAccount(ctx, t)
	case BreachTargetDomain:
		return h.searchDomain(ctx, t)
	default:
		return nil, nil
	}
}

// searchAccount — breachedaccount по почте: список брешей, где почта засветилась →
// account-находки (пароля HIBP не отдаёт, только факт присутствия).
func (h *hibpSource) searchAccount(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	endpoint := "https://haveibeenpwned.com/api/v3/breachedaccount/" + url.PathEscape(t.Value) + "?truncateResponse=false"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("hibp-api-key", h.key)
	body, ok, err := breachDo(ctx, h.cfg, "hibp", req)
	if err != nil || !ok {
		return nil, err
	}
	var breaches []struct {
		Name        string `json:"Name"`
		Domain      string `json:"Domain"`
		BreachDate  string `json:"BreachDate"`
		PwnCount    int    `json:"PwnCount"`
		DataClasses []any  `json:"DataClasses"`
	}
	if json.Unmarshal(body, &breaches) != nil {
		return nil, nil
	}
	out := make([]BreachLeak, 0, len(breaches))
	for _, b := range breaches {
		out = append(out, BreachLeak{
			Source:  "hibp",
			Kind:    "account",
			Subject: t.Value,
			Value:   "", // HIBP паролей не отдаёт — только факт присутствия
			Detail: map[string]any{
				"breach":       b.Name,
				"domain":       b.Domain,
				"breach_date":  b.BreachDate,
				"pwn_count":    b.PwnCount,
				"data_classes": b.DataClasses,
			},
		})
	}
	return out, nil
}

// searchDomain — Domain Search: GET /breacheddomain/{domain} (нужен hibp-api-key и
// верифицированное владение доменом). Ответ — карта {alias: [Breach1, ...]}, где alias
// это local-part засветившейся почты на домене. Каждый alias раскрываем в
// account-находку с subject=<alias>@<domain> (это и есть УТЁКШИЙ EMAIL-АККАУНТ).
func (h *hibpSource) searchDomain(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	endpoint := "https://haveibeenpwned.com/api/v3/breacheddomain/" + url.PathEscape(t.Value)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("hibp-api-key", h.key)
	body, ok, err := breachDo(ctx, h.cfg, "hibp", req)
	if err != nil || !ok {
		return nil, err
	}
	// {"alias":["Adobe","LinkedIn"], ...}; null/пусто → находок нет.
	var aliases map[string][]string
	if json.Unmarshal(body, &aliases) != nil {
		return nil, nil
	}
	out := make([]BreachLeak, 0, len(aliases))
	for alias, breaches := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		out = append(out, BreachLeak{
			Source:  "hibp",
			Kind:    "account",
			Subject: alias + "@" + t.Value,
			Value:   "", // домен-поиск отдаёт только факт присутствия, без пароля
			Detail: map[string]any{
				"breaches": breaches,
				"domain":   t.Value,
			},
		})
	}
	return out, nil
}

// ─────────────────────────── Dehashed (реальный) ───────────────────────────

// dehashedSource — Dehashed: поиск по домену/почте, basic-auth ключом вида
// "email:apikey" (если ':' нет — ключ уходит как пароль с пустым логином).
type dehashedSource struct {
	key string
	cfg BreachHTTPConfig
}

func (d *dehashedSource) Name() string { return "dehashed" }

func (d *dehashedSource) Enabled(keys BreachKeys) bool { return strings.TrimSpace(keys.Dehashed) != "" }

func (d *dehashedSource) Search(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	if strings.TrimSpace(d.key) == "" {
		return nil, nil
	}
	field := "email"
	if t.Kind == BreachTargetDomain {
		field = "domain"
	}
	q := url.Values{"query": {field + ":" + t.Value}, "size": {"100"}}
	req, err := http.NewRequest(http.MethodGet, "https://api.dehashed.com/search?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	user, pass := splitBasic(d.key)
	req.SetBasicAuth(user, pass)
	body, ok, err := breachDo(ctx, d.cfg, "dehashed", req)
	if err != nil || !ok {
		return nil, err
	}
	var env struct {
		Entries []breachEntry `json:"entries"`
	}
	if json.Unmarshal(body, &env) != nil {
		return nil, nil
	}
	return mapEntries("dehashed", t, env.Entries), nil
}

// splitBasic делит "user:pass" на пару; без ':' → логин пуст, вся строка — пароль.
func splitBasic(key string) (string, string) {
	if i := strings.IndexByte(key, ':'); i >= 0 {
		return key[:i], key[i+1:]
	}
	return "", key
}

// ─────────────────────────── IntelX ───────────────────────────

// intelxBase — база API IntelX для БЕСПЛАТНЫХ ключей (у платных — 2.intelx.io).
// Free-ключ на 2.intelx.io отдаёт 401, поэтому по умолчанию бьём в free.intelx.io.
const intelxBase = "https://free.intelx.io"

// intelxSource — IntelX intelligent search. Поиск двухшаговый: POST /intelligent/search
// стартует поиск и возвращает id, затем результаты добираются поллингом GET
// /intelligent/search/result (status 0 = ещё идёт, 1 = больше нет, 2 = истёк, 3 =
// пусто). Каждая запись — ссылка на дамп/паст/документ, где селектор засветился.
type intelxSource struct {
	key string
	cfg BreachHTTPConfig
}

func (s *intelxSource) Name() string { return "intelx" }

func (s *intelxSource) Enabled(keys BreachKeys) bool { return strings.TrimSpace(keys.IntelX) != "" }

func (s *intelxSource) Search(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	if strings.TrimSpace(s.key) == "" {
		return nil, nil // нет ключа → мягкий самопропуск
	}
	id, err := s.startSearch(ctx, t.Value)
	if err != nil || id == "" {
		return nil, err
	}
	var records []intelxRecord
	for i := 0; i < 5; i++ {
		recs, status, ferr := s.fetchResults(ctx, id)
		if ferr != nil {
			return mapIntelxRecords(t, records), ferr
		}
		records = append(records, recs...)
		if status != 0 || len(records) >= 100 { // 0 = добираем дальше; иначе готово
			break
		}
		select {
		case <-ctx.Done():
			return mapIntelxRecords(t, records), nil
		case <-time.After(700 * time.Millisecond):
		}
	}
	return mapIntelxRecords(t, records), nil
}

func (s *intelxSource) startSearch(ctx context.Context, term string) (string, error) {
	payload := map[string]any{
		"term": term, "buckets": []string{}, "lookuplevel": 0, "maxresults": 100,
		"timeout": 0, "datefrom": "", "dateto": "", "sort": 2, "media": 0, "terminate": []string{},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, intelxBase+"/intelligent/search", bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-key", s.key)
	req.Header.Set("Content-Type", "application/json")
	body, ok, err := breachDo(ctx, s.cfg, "intelx", req)
	if err != nil || !ok {
		return "", err
	}
	var r struct {
		ID     string `json:"id"`
		Status int    `json:"status"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Status == 2 { // невалидный term
		return "", nil
	}
	return r.ID, nil
}

func (s *intelxSource) fetchResults(ctx context.Context, id string) ([]intelxRecord, int, error) {
	q := url.Values{"id": {id}, "limit": {"100"}, "statistics": {"0"}, "previewlines": {"8"}}
	req, err := http.NewRequest(http.MethodGet, intelxBase+"/intelligent/search/result?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("x-key", s.key)
	body, ok, err := breachDo(ctx, s.cfg, "intelx", req)
	if err != nil || !ok {
		return nil, 0, err
	}
	var r struct {
		Records []intelxRecord `json:"records"`
		Status  int            `json:"status"`
	}
	_ = json.Unmarshal(body, &r)
	return r.Records, r.Status, nil
}

type intelxRecord struct {
	SystemID string `json:"systemid"`
	Name     string `json:"name"`
	Bucket   string `json:"bucket"`
	Date     string `json:"date"`
}

// mapIntelxRecords — записи IntelX → находки (source=intelx, kind=reference: ссылка
// на дамп/паст, где селектор засветился). Дедуп по (bucket,name).
func mapIntelxRecords(t BreachTarget, recs []intelxRecord) []BreachLeak {
	out := make([]BreachLeak, 0, len(recs))
	seen := map[string]struct{}{}
	for _, r := range recs {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = r.SystemID
		}
		key := r.Bucket + "\x00" + name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, BreachLeak{
			Source:  "intelx",
			Kind:    "reference",
			Subject: t.Value,
			Value:   name,
			Detail: map[string]any{
				"bucket":   r.Bucket,
				"name":     name,
				"date":     r.Date,
				"systemid": r.SystemID,
			},
		})
	}
	return out
}

// ─────────────────────────── LeakCheck (public) ───────────────────────────

// leakcheckSource — публичный БЕСПЛАТНЫЙ API LeakCheck (без ключа): по email или
// домену отдаёт названия дампов/бричей, где селектор засветился, и какие поля были
// раскрыты (есть password → kind=credential). Значений (паролей) публичный тир не
// отдаёт — только источники. Всегда активен.
type leakcheckSource struct{ cfg BreachHTTPConfig }

func (s *leakcheckSource) Name() string { return "leakcheck" }

func (s *leakcheckSource) Enabled(_ BreachKeys) bool { return true } // keyless free

func (s *leakcheckSource) Search(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	q := url.Values{"check": {t.Value}}
	req, err := http.NewRequest(http.MethodGet, "https://leakcheck.io/api/public?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	body, ok, err := breachDo(ctx, s.cfg, "leakcheck", req)
	if err != nil || !ok {
		return nil, err
	}
	var r struct {
		Success bool     `json:"success"`
		Found   int      `json:"found"`
		Fields  []string `json:"fields"`
		Sources []struct {
			Name string `json:"name"`
			Date string `json:"date"`
		} `json:"sources"`
	}
	_ = json.Unmarshal(body, &r)
	if !r.Success || r.Found == 0 {
		return nil, nil
	}
	breaches := make([]string, 0, len(r.Sources))
	for _, src := range r.Sources {
		if src.Name != "" {
			breaches = append(breaches, src.Name)
		}
	}
	kind := "account"
	for _, f := range r.Fields {
		if f == "password" {
			kind = "credential"
			break
		}
	}
	return []BreachLeak{{
		Source:  "leakcheck",
		Kind:    kind,
		Subject: t.Value,
		Value:   "",
		Detail: map[string]any{
			"breaches": breaches,
			"fields":   r.Fields,
			"found":    r.Found,
		},
	}}, nil
}

// ─────────────────────────── тонкие источники ───────────────────────────

// thinBreachSource — общий каркас «тонкого» источника: строит запрос (URL+auth)
// через build, гоняет общий HTTP-путь и парсит обобщённый JSON-ответ. Без ключа
// самопропускается (Enabled==false и Search возвращает пусто).
type thinBreachSource struct {
	name string
	key  string
	cfg  BreachHTTPConfig
	// keyless — источник работает БЕЗ ключа (бесплатный публичный API, напр. ProxyNova
	// COMB): всегда активен и не самопропускается по пустому ключу.
	keyless bool
	build   func(key string, t BreachTarget) (*http.Request, error)
}

func newThinBreachSource(name, key string, cfg BreachHTTPConfig, build func(string, BreachTarget) (*http.Request, error)) *thinBreachSource {
	return &thinBreachSource{name: name, key: key, cfg: cfg, build: build}
}

func (s *thinBreachSource) Name() string { return s.name }

func (s *thinBreachSource) Enabled(keys BreachKeys) bool {
	if s.keyless {
		return true // бесплатный источник — активен всегда
	}
	switch s.name {
	case "intelx":
		return strings.TrimSpace(keys.IntelX) != ""
	case "leakcheck":
		return strings.TrimSpace(keys.LeakCheck) != ""
	case "snusbase":
		return strings.TrimSpace(keys.Snusbase) != ""
	case "proxynova":
		return strings.TrimSpace(keys.ProxyNova) != ""
	}
	return false
}

func (s *thinBreachSource) Search(ctx context.Context, t BreachTarget) ([]BreachLeak, error) {
	if !s.keyless && strings.TrimSpace(s.key) == "" {
		return nil, nil // нет ключа → мягкий самопропуск
	}
	req, err := s.build(s.key, t)
	if err != nil {
		return nil, err
	}
	body, ok, err := breachDo(ctx, s.cfg, s.name, req)
	if err != nil || !ok {
		return nil, err
	}
	return parseGenericBreach(s.name, t, body), nil
}

// breachEntry — обобщённая строка утечки (общие поля большинства breach-API).
type breachEntry struct {
	Email          string `json:"email"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	HashedPassword string `json:"hashed_password"`
	Hash           string `json:"hash"`
	Source         string `json:"source"`
	Database       string `json:"database_name"`
}

// parseGenericBreach разбирает обобщённый ответ (обёртки entries/result/data или
// голый массив) в находки.
func parseGenericBreach(source string, t BreachTarget, body []byte) []BreachLeak {
	var env struct {
		Entries []breachEntry `json:"entries"`
		Result  []breachEntry `json:"result"`
		Data    []breachEntry `json:"data"`
	}
	_ = json.Unmarshal(body, &env)
	rows := append([]breachEntry{}, env.Entries...)
	rows = append(rows, env.Result...)
	rows = append(rows, env.Data...)
	if len(rows) == 0 {
		var arr []breachEntry
		if json.Unmarshal(body, &arr) == nil {
			rows = arr
		}
	}
	return mapEntries(source, t, rows)
}

// mapEntries приводит обобщённые строки к BreachLeak. Есть пароль/хеш → kind=credential,
// иначе account. Subject — почта строки (или цель поиска, если пусто).
func mapEntries(source string, t BreachTarget, rows []breachEntry) []BreachLeak {
	out := make([]BreachLeak, 0, len(rows))
	for _, e := range rows {
		value := e.Password
		if value == "" {
			value = e.HashedPassword
		}
		if value == "" {
			value = e.Hash
		}
		kind := "account"
		if value != "" {
			kind = "credential"
		}
		subject := e.Email
		if subject == "" {
			subject = t.Value
		}
		out = append(out, BreachLeak{
			Source:  source,
			Kind:    kind,
			Subject: subject,
			Value:   value,
			Detail: map[string]any{
				"database": firstNonEmpty(e.Database, e.Source),
				"username": e.Username,
				"email":    e.Email,
			},
		})
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
