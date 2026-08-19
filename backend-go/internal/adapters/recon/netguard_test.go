package recon

import "testing"

func TestIsDisallowedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"169.254.169.254",           // cloud metadata — link-local
		"0.0.0.0", "::1", "fe80::1", // unspecified / loopback / link-local v6
		"100.64.0.1",               // CGNAT
		"240.0.0.1",                // reserved
		"224.0.0.1",                // multicast
		"::ffff:127.0.0.1",         // IPv4-mapped loopback
		"::ffff:169.254.169.254",   // IPv4-mapped metadata
		"2002:a9fe:a9fe::",         // 6to4 wrapping 169.254.169.254
		"2001:0:0:0:0:0:80ff:fffe", // Teredo wrapping 127.0.0.1
		"not-an-ip",                // мусор запрещён
	}
	for _, a := range blocked {
		if !IsDisallowedIP(a) {
			t.Errorf("%s должен быть запрещён, но разрешён", a)
		}
	}

	allowed := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"2606:4700:4700::1111", // Cloudflare DNS — внешний IPv6
	}
	for _, a := range allowed {
		if IsDisallowedIP(a) {
			t.Errorf("%s должен быть разрешён, но запрещён", a)
		}
	}
}
