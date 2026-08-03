"""Определение принадлежности адреса сетям Cloudflare.

Список статический (источник — cloudflare.com/ips-v4 и /ips-v6), обновляется
руками: детект должен быть чистой функцией от адреса, без сетевых запросов в
рантайме. Иначе пришлось бы ходить наружу из фазы резолва — а она специально
сделана без побочных эффектов и без обхода SSRF-гейта.

Признак пересчитывается при каждой записи адреса, поэтому «протухнуть» в БД
он не может: обновили список — следующий импорт проставит новое значение.
"""

from __future__ import annotations

import ipaddress

# Дата последней сверки списка с cloudflare.com/ips.
CLOUDFLARE_RANGES_UPDATED = "2026-07-19"

CLOUDFLARE_IPV4_CIDRS: tuple[str, ...] = (
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
)

CLOUDFLARE_IPV6_CIDRS: tuple[str, ...] = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

_CF_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(cidr) for cidr in (*CLOUDFLARE_IPV4_CIDRS, *CLOUDFLARE_IPV6_CIDRS)
)


def is_cloudflare_ip(addr: str | None) -> bool:
    """True, если адрес принадлежит опубликованным сетям Cloudflare."""
    if not addr:
        return False
    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip_obj in net for net in _CF_NETWORKS)
