// Package recon содержит адаптеры рекон-фермы. netguard — сетевые предикаты
// SSRF-защиты без зависимостей от БД/моделей (порт app/netguard.py): рекон-ферма
// и прикладные сервисы пользуются одними правилами «куда ходить нельзя».
package recon

import "net/netip"

// IsInternalIP — внутренний/системный адрес (цель SSRF-защиты).
func isInternalIP(ip netip.Addr) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() ||
		isReserved(ip)
}

// isReserved закрывает диапазоны, которые netip не помечает отдельным предикатом,
// но Python ipaddress.is_reserved считает системными (например 240.0.0.0/4,
// 0.0.0.0/8, 100.64.0.0/10 CGNAT, 192.0.0.0/24, 198.18.0.0/15 и т.п.).
func isReserved(ip netip.Addr) bool {
	for _, p := range reservedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

var reservedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this host"
	"100.64.0.0/10",   // CGNAT (RFC 6598)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved (RFC 1112)
	"2001:db8::/32",   // documentation
	"100::/64",        // discard-only (RFC 6666)
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// embeddedV4 разворачивает IPv4, «завёрнутый» в IPv6 (mapped ::ffff:a.b.c.d,
// 6to4 2002::, Teredo 2001::), чтобы ::ffff:169.254.169.254 не прошёл как внешний
// IPv6 и не увёл пробив на metadata-эндпоинт. Возвращает встроенные v4-адреса.
func embeddedV4(ip netip.Addr) []netip.Addr {
	var out []netip.Addr
	if ip.Is4In6() {
		out = append(out, ip.Unmap())
	}
	a16 := ip.As16()
	// 6to4: 2002:AABB:CCDD::/16 -> A.B.C.D в байтах 2..5.
	if a16[0] == 0x20 && a16[1] == 0x02 {
		out = append(out, netip.AddrFrom4([4]byte{a16[2], a16[3], a16[4], a16[5]}))
	}
	// Teredo: 2001:0000::/32 — клиентский IPv4 в последних 4 байтах, XOR 0xff.
	if a16[0] == 0x20 && a16[1] == 0x01 && a16[2] == 0x00 && a16[3] == 0x00 {
		out = append(out, netip.AddrFrom4([4]byte{
			a16[12] ^ 0xff, a16[13] ^ 0xff, a16[14] ^ 0xff, a16[15] ^ 0xff,
		}))
	}
	return out
}

// IsDisallowedIP — true, если адрес внутренний/приватный/системный (SSRF-гейт).
// Нераспознанный адрес тоже запрещён: лучше отклонить непонятное, чем пустить.
func IsDisallowedIP(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return true
	}
	if isInternalIP(ip) {
		return true
	}
	for _, v4 := range embeddedV4(ip) {
		if isInternalIP(v4) {
			return true
		}
	}
	return false
}
