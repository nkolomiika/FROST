package recon

import (
	"time"

	"github.com/nkolomiika/frost/config"
	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

func secs(v float64) time.Duration { return time.Duration(v * float64(time.Second)) }

// SettingsFromConfig собирает сетевой тюнинг adapters/recon из config.Config.
func SettingsFromConfig(c *config.Config) reconnet.Settings {
	return reconnet.Settings{
		FarmMaxTargets:            c.FarmMaxTargets,
		FarmMaxPortsPerHost:       c.FarmMaxPortsPerHost,
		FarmProbeTimeout:          secs(c.FarmProbeTimeoutSeconds),
		FarmMaxConcurrency:        c.FarmMaxConcurrency,
		FarmMaxRawBytes:           c.FarmMaxRawBytes,
		FarmAllowPrivate:          c.FarmAllowPrivateTargets,
		FarmReverseDNSEnabled:     c.FarmReverseDNSEnabled,
		FarmReverseDNSTimeout:     secs(c.FarmReverseDNSTimeoutSeconds),
		FarmHostResolveIPsEnabled: c.FarmHostResolveIPsEnabled,
		FarmIPResolveHostsEnabled: c.FarmIPResolveHostsEnabled,

		JSMaxFilesPerHost:  c.JSFarmMaxFilesPerHost,
		JSMaxFileBytes:     c.JSFarmMaxFileBytes,
		JSDownloadTimeout:  secs(c.JSFarmDownloadTimeoutSeconds),
		JSMaxConcurrency:   c.JSFarmMaxConcurrency,
		JSMaxInflightBytes: c.JSFarmMaxInflightBytes,
		JSMaxTotalFiles:    c.JSFarmMaxTotalFiles,
		JSMineEnabled:      c.JSMineEnabled,
		JsluiceBin:         c.JsluiceBin,
		TrufflehogBin:      c.TrufflehogBin,
		JSMineTimeout:      secs(c.JSMineTimeoutSecs),
		GithubScanTimeout:  secs(c.GithubScanTimeoutSecs),

		ServicesDetectEnabled:  c.ServicesDetectEnabled,
		ServicesDetectEngine:   c.ServicesDetectEngine,
		ServicesHttpxBin:       c.ServicesHttpxBin,
		ServicesWhatwebBin:     c.ServicesWhatwebBin,
		ServicesDetectTimeout:  secs(c.ServicesDetectTimeoutSeconds),
		ServicesMaxConcurrency: c.ServicesMaxConcurrency,

		SubsCrtshEnabled:     c.SubsCrtshEnabled,
		SubsCrtshTimeout:     secs(c.SubsCrtshTimeoutSeconds),
		SubsSubfinderEnabled: c.SubsSubfinderEnabled,
		SubsSubfinderBin:     c.SubsSubfinderBin,
		SubsSubfinderTimeout: secs(c.SubsSubfinderTimeoutSeconds),
		SubsMaxResults:       c.SubsMaxResults,

		PortscanNmapBin:    c.PortscanNmapBin,
		PortscanTopPorts:   c.PortscanTopPorts,
		PortscanTimeout:    secs(c.PortscanTimeoutSeconds),
		PortscanMaxTargets: c.PortscanMaxTargets,

		DnsxBin:          c.ReconDnsxBin,
		DnsxBruteTimeout: secs(c.ReconDnsxBruteTimeoutSecs),

		KatanaBin:           c.ReconKatanaBin,
		GauBin:              c.ReconGauBin,
		WaybackurlsBin:      c.ReconWaybackurlsBin,
		FfufBin:             c.ReconFfufBin,
		EndpointsTimeout:    secs(c.ReconEndpointsTimeoutSec),
		EndpointsMaxPerHost: c.ReconEndpointsMaxPerHost,
		EndpointsMaxTotal:   c.ReconEndpointsMaxTotal,
	}
}

// ConfigFromConfig собирает оркестрационный тюнинг из config.Config.
func ConfigFromConfig(c *config.Config) Config {
	return Config{
		WorkerEnabled:    c.ReconWorkerEnabled,
		MaxAttempts:      int32(c.ReconMaxAttempts),
		StaleSeconds:     int32(c.ReconStaleJobSeconds),
		FarmStaleSeconds: int32(c.ReconFarmStaleJobSeconds),
		ResultMaxItems:   c.ReconResultMaxItems,
	}
}
