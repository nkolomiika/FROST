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
}

func (s Settings) maxConcurrency() int {
	if s.FarmMaxConcurrency <= 0 {
		return 1
	}
	return s.FarmMaxConcurrency
}
