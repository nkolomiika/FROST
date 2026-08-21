package recon

// FarmConfig — пер-проектная конфигурация recon-фермы (recon-стек). Хранится в
// БД как JSONB-блоб; на чтении дефолты доклеиваются (LoadFarmConfig грузит
// DefaultFarmConfig и накладывает сверху сохранённый JSON — отсутствующие поля
// остаются дефолтными). Snake_case json-теги фиксируют формат провода для фронта.
type FarmConfig struct {
	// Global — глобальные параметры прогонов фермы.
	Mode        string `json:"mode"`        // "passive" | "active"
	RateLimit   int    `json:"rate_limit"`  // rps
	Concurrency int    `json:"concurrency"` //

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
		Mode:        "active",
		RateLimit:   20,
		Concurrency: 10,

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
	if c.Mode != "passive" {
		c.Mode = "active"
	}
	c.RateLimit = clampInt(c.RateLimit, 1, 500)
	c.Concurrency = clampInt(c.Concurrency, 1, 100)
	c.KatanaDepth = clampInt(c.KatanaDepth, 1, 10)
	c.SubsMaxResults = clampInt(c.SubsMaxResults, 1, 100000)
	c.HttpxThreads = clampInt(c.HttpxThreads, 1, 1000)
}
