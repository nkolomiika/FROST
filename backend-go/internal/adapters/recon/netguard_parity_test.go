package recon

import "testing"

// Дополняет netguard_test.go до паритета с test_netguard.py: unique-local v6,
// IPv4-mapped приватный, 6to4 с приватным встроенным v4, и — что важно —
// mapped публичный не должен over-block'аться.

func TestIsDisallowedIP_parityDisallowed(t *testing.T) {
	blocked := []string{
		"10.0.0.5",        // private
		"fc00::1",         // unique-local v6
		"::ffff:10.0.0.1", // mapped → private
		"2002:a00:1::",    // 6to4, встроенный 10.0.0.1
	}
	for _, a := range blocked {
		if !IsDisallowedIP(a) {
			t.Errorf("%s должен быть запрещён, но разрешён", a)
		}
	}
}

func TestIsDisallowedIP_parityAllowed(t *testing.T) {
	allowed := []string{
		"104.16.0.1",     // публичный (Cloudflare-диапазон, но не приватный)
		"2606:4700::1",   // публичный v6
		"::ffff:8.8.8.8", // mapped публичный — обёртка не должна over-block'ать
	}
	for _, a := range allowed {
		if IsDisallowedIP(a) {
			t.Errorf("%s должен быть разрешён, но запрещён", a)
		}
	}
}
