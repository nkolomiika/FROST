package inventory

import "net"

// Диапазоны Cloudflare (порт app/cloudflare.py; источник — cloudflare.com/ips).
// Список статический и обновляется руками: детект — чистая функция от адреса,
// без сетевых запросов в рантайме.
var cloudflareCIDRs = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

var cloudflareNets = parseCloudflareNets()

func parseCloudflareNets() []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cloudflareCIDRs))
	for _, cidr := range cloudflareCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		nets = append(nets, n)
	}
	return nets
}

// IsCloudflareIP — true, если адрес принадлежит опубликованным сетям Cloudflare
// (порт is_cloudflare_ip). Пустой/невалидный адрес → false.
func IsCloudflareIP(addr string) bool {
	if addr == "" {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range cloudflareNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
