"""SSRF-гейт: что пропускаем, что режем. Версионно-независимая проверка обёрток."""

import pytest

from app.netguard import is_disallowed_ip


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",  # loopback
        "10.0.0.5",  # private
        "192.168.1.1",  # private
        "172.16.0.1",  # private
        "169.254.169.254",  # link-local (cloud metadata)
        "0.0.0.0",  # unspecified
        "224.0.0.1",  # multicast
        "::1",  # loopback v6
        "fc00::1",  # unique-local v6
        "fe80::1",  # link-local v6
        # Встроенный IPv4 внутри IPv6 — не должен «просочиться» как внешний.
        "::ffff:169.254.169.254",  # mapped → metadata
        "::ffff:10.0.0.1",  # mapped → private
        "::ffff:127.0.0.1",  # mapped → loopback
        "2002:a00:1::",  # 6to4, встроенный 10.0.0.1
        "not-an-ip",  # мусор → отклоняем
    ],
)
def test_disallowed(addr: str) -> None:
    assert is_disallowed_ip(addr) is True


@pytest.mark.parametrize(
    "addr",
    [
        "8.8.8.8",
        "1.1.1.1",
        "104.16.0.1",  # публичный (Cloudflare-диапазон, но не приватный)
        "2606:4700::1",  # публичный v6
        "::ffff:8.8.8.8",  # mapped публичный — пропускаем (обёртка не должна over-block)
    ],
)
def test_allowed(addr: str) -> None:
    assert is_disallowed_ip(addr) is False
