"""Scanner: скан портов — парсер nmap XML и запись результатов."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.enums import PortState
from app.farm.core import ParsedTarget
from app.farm.portscan import PortScanFarmService, parse_nmap_xml
from app.farm.resolver import ResolvedHost

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/></port>
      <port protocol="udp" portid="53"><state state="open"/></port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.9" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="open"/></port></ports>
  </host>
</nmaprun>"""


def test_parse_nmap_xml_open_tcp_only() -> None:
    parsed = parse_nmap_xml(NMAP_XML)
    assert parsed["93.184.216.34"] == [80, 443]  # closed 8080 и udp 53 отброшены
    assert parsed["10.0.0.9"] == [22]


def test_parse_nmap_xml_garbage() -> None:
    assert parse_nmap_xml("") == {}
    assert parse_nmap_xml("<broken") == {}


def _mock_db() -> MagicMock:
    db = MagicMock()
    db.scalar = AsyncMock(return_value=None)  # ничего не существует
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_probe_and_import_scans_only_external(monkeypatch: pytest.MonkeyPatch) -> None:
    """Внутренний адрес не сканируется, внешний — да; порты пишутся как OPEN."""
    svc = PortScanFarmService(_mock_db())
    svc.audit.log = AsyncMock()
    monkeypatch.setattr("app.farm.portscan.ws_manager.broadcast", AsyncMock())

    resolved = {
        "ext.com": ResolvedHost(ip="93.184.216.34", ips=["93.184.216.34"]),
        "intranet.corp": ResolvedHost(ip="10.0.0.9", ips=["10.0.0.9"], blocked=True),
    }
    svc._resolve_dns = AsyncMock(return_value=resolved)

    created_ports: list[int] = []
    host = MagicMock(id=1, hostname="ext.com", ip_address="93.184.216.34")
    svc._find_or_create_host = AsyncMock(return_value=(host, True))
    svc._ensure_ips = AsyncMock(return_value=MagicMock(id=11))

    async def fake_upsert(h, ip_row, port_number):
        created_ports.append(port_number)
        return True

    svc._upsert_scan_port = fake_upsert

    scanned_ips: list[str] = []

    async def scanner(ips: list[str]) -> dict[str, list[int]]:
        scanned_ips.extend(ips)
        return {"93.184.216.34": [80, 443]}

    result = await svc.probe_and_import(1, "ext.com\nintranet.corp", 7, scanner=scanner)

    assert scanned_ips == ["93.184.216.34"]  # внутренний 10.0.0.9 не ушёл в nmap
    assert created_ports == [80, 443]
    assert result.ports_found == 2
    assert result.ports_created == 2
    assert result.hosts_up == 1
    assert result.targets_scanned == 2
