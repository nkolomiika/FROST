"""Сетевые предикаты для SSRF-защиты — без зависимостей от БД и моделей.

Вынесено из JiraIntegrationService, чтобы модули рекон-фермы (farm.core,
farm.resolver) могли пользоваться теми же правилами, не втягивая app.services
со всей ORM. JiraIntegrationService._is_disallowed_ip делегирует сюда.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator

_IpAddr = ipaddress.IPv4Address | ipaddress.IPv6Address


def _is_internal(ip: _IpAddr) -> bool:
    """Внутренний/системный адрес — цель SSRF-защиты."""
    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _embedded_v4(ip: _IpAddr) -> Iterator[ipaddress.IPv4Address]:
    """IPv4, «завёрнутый» в IPv6: mapped (``::ffff:a.b.c.d``), 6to4 (``2002::``),
    Teredo (``2001::``).

    На части рантаймов ``is_private`` и соседние свойства не смотрят внутрь
    обёртки (историческое поведение CPython < 3.12.4, gh-113171). Чтобы гейт не
    зависел от версии интерпретатора, разворачиваем встроенный адрес сами и
    проверяем его отдельно — иначе ``::ffff:169.254.169.254`` мог бы пройти как
    «внешний» IPv6 и увести пробив на облачный metadata-эндпоинт.
    """
    for attr in ("ipv4_mapped", "sixtofour"):
        v4 = getattr(ip, attr, None)
        if v4 is not None:
            yield v4
    teredo = getattr(ip, "teredo", None)
    if teredo:  # (server, client) — блокируем, если любой конец внутренний
        yield from (part for part in teredo if part is not None)


def is_disallowed_ip(addr: str) -> bool:
    """True, если IP-адрес внутренний/приватный/системный — для SSRF-защиты.

    Нераспознанный адрес тоже запрещён: лучше отклонить непонятное, чем пустить.
    Встроенный в IPv6 IPv4 (mapped/6to4/Teredo) разворачивается и проверяется
    отдельно — версионно-независимо (см. ``_embedded_v4``).
    """
    try:
        ip_obj = ipaddress.ip_address(addr)
    except ValueError:
        return True
    if _is_internal(ip_obj):
        return True
    return any(_is_internal(v4) for v4 in _embedded_v4(ip_obj))
