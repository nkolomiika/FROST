package inventory

import "testing"

// Порт backend/tests/test_ip_farm_service.py::test_is_cloudflare_ip —
// классификация адреса по опубликованным сетям Cloudflare (чистая функция).
func TestIsCloudflareIP(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"104.16.0.1", true},   // 104.16.0.0/13
		{"172.64.1.1", true},   // 172.64.0.0/13
		{"2606:4700::1", true}, // 2606:4700::/32
		{"93.184.216.34", false},
		{"8.8.8.8", false},
		{"не-адрес", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsCloudflareIP(c.addr); got != c.want {
			t.Errorf("IsCloudflareIP(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
