package recon

import (
	"strings"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// FarmConfig — пер-проектная конфигурация recon-фермы (recon-стек). Хранится в
// БД как JSONB-блоб; на чтении дефолты доклеиваются (LoadFarmConfig грузит
// DefaultFarmConfig и накладывает сверху сохранённый JSON — отсутствующие поля
// остаются дефолтными). Snake_case json-теги фиксируют формат провода для фронта.
type FarmConfig struct {
	// Global — высокоуровневые ручки прогона (единственное, что видит пользователь).
	// Mode "both" гоняет пассивный и активный сбор ОДНОВРЕМЕННО.
	Mode          string `json:"mode"`            // "passive" | "active" | "both"
	WordlistSize  string `json:"wordlist_size"`   // "small" | "medium" | "large" (файл выбирает FROST)
	RateLimit     int    `json:"rate_limit"`      // rps
	Concurrency   int    `json:"concurrency"`     // параллельных воркеров
	PortScanScope string `json:"port_scan_scope"` // "top1000" | "all"
	CrawlDepth    int    `json:"crawl_depth"`     // глубина краула (1..10)

	// Выбор словаря брута поддоменов. Приоритет разрешения (см. Materialize):
	//   SubdomainWordlistID>0 → кастомный словарь (recon_wordlists) из MinIO в temp;
	//   иначе SubdomainWordlistPath!="" → забандленный на диске файл по ОТНОСИТЕЛЬНОМУ
	//   пути под WordlistDir (SecLists/n0kovo, валидируется сервером);
	//   иначе → бандл-тир из WordlistSize.
	SubdomainWordlistID   int    `json:"subdomain_wordlist_id"`
	SubdomainWordlistPath string `json:"subdomain_wordlist_path"`

	// Стадия эндпоинтов: режим сбора и словарь дир-фаззинга (ffuf).
	//   EndpointsMode "passive" → gau+waybackurls; "active" → katana+ffuf;
	//   "both" (дефолт) → всё. Тумблеры Katana/Gau/Waybackurls остаются доп.фильтром.
	//   Словарь ffuf: EndpointsWordlistID>0 → кастомный; иначе EndpointsWordlistPath!=""
	//   → забандленный файл по пути; иначе → бандл-тир (WordlistSize). ffuf включается,
	//   если задан id ИЛИ путь.
	EndpointsMode         string `json:"endpoints_mode"`
	EndpointsWordlistID   int    `json:"endpoints_wordlist_id"`
	EndpointsWordlistPath string `json:"endpoints_wordlist_path"`

	// Stage toggles — пер-стадийное включение полного прогона (farm_run). Дефолт
	// true у всех: пропущенная в сохранённом JSON стадия остаётся включённой (см.
	// GetFarmConfig — оверлей поверх DefaultFarmConfig). stage_subdomains off →
	// discovery пропускается, поздние стадии работают по СУЩЕСТВУЮЩИМ хостам проекта.
	StageSubdomains    bool `json:"stage_subdomains"`
	StageEndpoints     bool `json:"stage_endpoints"`
	StageJs            bool `json:"stage_js"`
	StagePorts         bool `json:"stage_ports"`
	StageLeaks         bool `json:"stage_leaks"`
	StageAccountSearch bool `json:"stage_account_search"`

	// Leaks — входы стадии утечек (gated: stage_leaks). Github-URL'ы сканируются
	// trufflehog'ом (секреты), домены/почты пробиваются по breach-источникам с
	// сконфигурированными ключами. Пустые списки → стадия ничего не делает.
	// Back-compat: отсутствие полей в сохранённом JSON = nil = «не задано».
	LeaksGithub    []string `json:"leaks_github"`
	LeaksDomains   []string `json:"leaks_domains"`
	LeaksEmails    []string `json:"leaks_emails"`
	LeaksCompanies []string `json:"leaks_companies"`

	// Subdomains — сбор поддоменов.
	Subfinder         bool `json:"subfinder"`
	Assetfinder       bool `json:"assetfinder"`
	AmassPassive      bool `json:"amass_passive"`
	Crtsh             bool `json:"crtsh"`
	CtTimeCorrelation bool `json:"ct_time_correlation"`
	ActiveBrute       bool `json:"active_brute"`
	SubsMaxResults    int  `json:"subs_max_results"`

	// Liveness — проверка живости/резолвинг.
	Dnsx         bool `json:"dnsx"`
	Httpx        bool `json:"httpx"`
	HttpxThreads int  `json:"httpx_threads"`

	// JS mining — добыча секретов/эндпоинтов из JS.
	JsMineEnabled          bool `json:"js_mine_enabled"`
	TrufflehogVerifiedOnly bool `json:"trufflehog_verified_only"`

	// Crawl/URLs — краулинг и сбор URL.
	Katana      bool `json:"katana"`
	Gau         bool `json:"gau"`
	Waybackurls bool `json:"waybackurls"`
	KatanaDepth int  `json:"katana_depth"`

	// Parameters — обнаружение параметров.
	ParamDiscovery bool `json:"param_discovery"`

	// Dir fuzz — дир-фаззинг.
	DirFuzz      bool   `json:"dir_fuzz"`
	FuzzWordlist string `json:"fuzz_wordlist"`

	// Vulns — сканирование уязвимостей.
	Nuclei         bool   `json:"nuclei"`
	NucleiSeverity string `json:"nuclei_severity"`
}

// DefaultFarmConfig возвращает дефолтную конфигурацию фермы (зеркало
// одобренного recon-стека). Используется как база при чтении и как ответ, когда
// у проекта ещё нет сохранённой строки.
func DefaultFarmConfig() FarmConfig {
	return FarmConfig{
		Mode:          "both",
		WordlistSize:  "medium",
		RateLimit:     20,
		Concurrency:   10,
		PortScanScope: "top1000",
		CrawlDepth:    3,

		SubdomainWordlistID:   0,
		SubdomainWordlistPath: "",
		EndpointsMode:         "both",
		EndpointsWordlistID:   0,
		EndpointsWordlistPath: "",

		StageSubdomains:    true,
		StageEndpoints:     true,
		StageJs:            true,
		StagePorts:         true,
		StageLeaks:         false, // стадия утечек по умолчанию выключена (доп. вход/ключи)
		StageAccountSearch: false, // поиск учёток — отдельная стадия, по умолчанию выключена

		Subfinder:         true,
		Assetfinder:       true,
		AmassPassive:      false,
		Crtsh:             true,
		CtTimeCorrelation: false,
		ActiveBrute:       false,
		SubsMaxResults:    2000,

		Dnsx:         true,
		Httpx:        true,
		HttpxThreads: 50,

		JsMineEnabled:          true,
		TrufflehogVerifiedOnly: false,

		Katana:      true,
		Gau:         true,
		Waybackurls: true,
		KatanaDepth: 3,

		ParamDiscovery: true,

		DirFuzz:      false,
		FuzzWordlist: "",

		Nuclei:         false,
		NucleiSeverity: "medium,high,critical",
	}
}

// clampInt возвращает v, зажатый в [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Sanitize приводит конфиг к безопасным границам: зажимает числа в допустимые
// диапазоны и нормализует Mode ("passive"|"active"). Вызывается перед сохранением.
func (c *FarmConfig) Sanitize() {
	switch c.Mode {
	case "passive", "active", "both":
	default:
		c.Mode = "both"
	}
	switch c.WordlistSize {
	case "small", "medium", "large":
	default:
		c.WordlistSize = "medium"
	}
	if c.PortScanScope != "all" {
		c.PortScanScope = "top1000"
	}
	switch c.EndpointsMode {
	case "passive", "active", "both":
	default:
		c.EndpointsMode = "both"
	}
	// id словарей неотрицательны (0 = бандл-дефолт).
	if c.SubdomainWordlistID < 0 {
		c.SubdomainWordlistID = 0
	}
	if c.EndpointsWordlistID < 0 {
		c.EndpointsWordlistID = 0
	}
	// Пути забандленных словарей: чистим до безопасного относительного пути под
	// WordlistDir; абсолютный/'..'/выход наружу → "" (используется id или тир).
	// Синтаксическая проверка; финальная валидация с проверкой файла — на запуске
	// инструмента (ResolveWordlistPath в Materialize).
	c.SubdomainWordlistPath = reconnet.SanitizeWordlistRelPath(c.SubdomainWordlistPath)
	c.EndpointsWordlistPath = reconnet.SanitizeWordlistRelPath(c.EndpointsWordlistPath)
	c.CrawlDepth = clampInt(c.CrawlDepth, 1, 10)
	c.RateLimit = clampInt(c.RateLimit, 1, 500)
	c.Concurrency = clampInt(c.Concurrency, 1, 100)
	c.KatanaDepth = clampInt(c.KatanaDepth, 1, 10)
	c.SubsMaxResults = clampInt(c.SubsMaxResults, 1, 100000)
	c.HttpxThreads = clampInt(c.HttpxThreads, 1, 1000)

	// Leaks-входы: trim → нормализация → drop невалидных → дедуп → cap.
	c.LeaksGithub = sanitizeStrList(c.LeaksGithub, leaksInputCap, normalizeGithubInput)
	c.LeaksDomains = sanitizeStrList(c.LeaksDomains, leaksInputCap, normalizeDomainInput)
	c.LeaksEmails = sanitizeStrList(c.LeaksEmails, leaksInputCap, normalizeEmailInput)
	c.LeaksCompanies = sanitizeStrList(c.LeaksCompanies, leaksInputCap, normalizeCompanyInput)
}

// leaksInputCap — верхняя граница числа входов на каждый список leaks (защита от
// раздутого JSON и слишком длинного прогона).
const leaksInputCap = 200

// sanitizeStrList нормализует каждый элемент (norm возвращает канон и ok), выкидывает
// невалидные/пустые/дубли (по канону) с сохранением порядка и обрезает по cap.
func sanitizeStrList(in []string, cap int, norm func(string) (string, bool)) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		s, ok := norm(strings.TrimSpace(v))
		if !ok || s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= cap {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeGithubInput валидирует github-URL через ParseGithubTarget (тот же
// разбор, что и у скана) и приводит к каноничному виду. Невалидный → drop.
func normalizeGithubInput(v string) (string, bool) {
	t, err := reconnet.ParseGithubTarget(v)
	if err != nil {
		return "", false
	}
	if t.IsOrg {
		return "https://github.com/" + t.Org, true
	}
	return t.Repo, true
}

// normalizeDomainInput приводит домен к нижнему регистру и отсеивает мусор (пробелы,
// слэши, отсутствие точки). Хвостовая точка убирается.
func normalizeDomainInput(v string) (string, bool) {
	v = strings.ToLower(strings.TrimSuffix(v, "."))
	if v == "" || strings.ContainsAny(v, " /\\") || !strings.Contains(v, ".") {
		return "", false
	}
	return v, true
}

// normalizeEmailInput — базовая проверка формы почты (ровно один '@', домен с точкой,
// без пробелов). Приводит к нижнему регистру.
func normalizeEmailInput(v string) (string, bool) {
	v = strings.ToLower(v)
	if v == "" || strings.ContainsAny(v, " \t") || strings.Count(v, "@") != 1 {
		return "", false
	}
	at := strings.IndexByte(v, '@')
	local, dom := v[:at], v[at+1:]
	if local == "" || dom == "" || !strings.Contains(dom, ".") || strings.HasPrefix(dom, ".") || strings.HasSuffix(dom, ".") {
		return "", false
	}
	return v, true
}

// normalizeCompanyInput — название компании для LinkedIn-энумерации: непустое, не
// слишком длинное. Пробелы/регистр сохраняем (идут в поисковый запрос как есть).
func normalizeCompanyInput(v string) (string, bool) {
	if v == "" || len(v) > 120 {
		return "", false
	}
	return v, true
}
