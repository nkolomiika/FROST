package recon

import "time"

// Settings — тюнинг рекон-фермы, инъектируемый в чистые/сетевые функции адаптера
// (порт глобального settings из app/config.py, но без зависимости на config-пакет).
// Приложение (app/recon) собирает его из config.Config и передаёт сюда.
type Settings struct {
	FarmMaxTargets            int
	FarmMaxPortsPerHost       int
	FarmProbeTimeout          time.Duration
	FarmMaxConcurrency        int
	FarmMaxRawBytes           int
	FarmAllowPrivate          bool
	FarmReverseDNSEnabled     bool
	FarmReverseDNSTimeout     time.Duration
	FarmHostResolveIPsEnabled bool
	FarmIPResolveHostsEnabled bool

	JSMaxFilesPerHost int
	JSMaxFileBytes    int
	JSDownloadTimeout time.Duration
	JSMaxConcurrency  int
	JSMaxTotalFiles   int

	// JS-майнинг внешними инструментами (jsluice + trufflehog).
	JSMineEnabled bool
	JsluiceBin    string
	TrufflehogBin string
	JSMineTimeout time.Duration

	// GitHub secret-scan (trufflehog github) — отдельный таймаут (скан репозитория/
	// org длиннее файлового майнинга).
	GithubScanTimeout time.Duration

	ServicesDetectEnabled  bool
	ServicesDetectEngine   string
	ServicesHttpxBin       string
	ServicesWhatwebBin     string
	ServicesDetectTimeout  time.Duration
	ServicesMaxConcurrency int

	SubsCrtshEnabled     bool
	SubsCrtshTimeout     time.Duration
	SubsSubfinderEnabled bool
	SubsSubfinderBin     string
	SubsSubfinderTimeout time.Duration
	SubsMaxResults       int

	PortscanNmapBin    string
	PortscanTopPorts   int
	PortscanTimeout    time.Duration
	PortscanMaxTargets int

	// Активный брут поддоменов dnsx в полном прогоне фермы (kind='farm_run').
	DnsxBin          string
	DnsxBruteTimeout time.Duration

	// Стадия эндпоинтов полного прогона фермы: katana (краул) + gau + waybackurls.
	KatanaBin        string
	GauBin           string
	WaybackurlsBin   string
	EndpointsTimeout time.Duration
}

func (s Settings) maxConcurrency() int {
	if s.FarmMaxConcurrency <= 0 {
		return 1
	}
	return s.FarmMaxConcurrency
}

// jsMineConfig собирает конфиг внешнего JS-майнинга из Settings.
func (s Settings) jsMineConfig() JSMineConfig {
	return JSMineConfig{
		Enabled:       s.JSMineEnabled,
		JsluiceBin:    s.JsluiceBin,
		TrufflehogBin: s.TrufflehogBin,
		Timeout:       s.JSMineTimeout,
	}
}
