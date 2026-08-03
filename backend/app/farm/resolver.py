"""Рекон-ферма, фаза 2: прямой и обратный резолв. БД не трогает.

Прямой резолв возвращает ВСЕ адреса цели (а не первый), потому что у одного
имени за CDN их обычно несколько — все они попадают в ips хоста.

Обратный резолв собирает имена из трёх источников и ничего не выбрасывает:

  1. PTR (`gethostbyaddr`) — имя + алиасы, source="ptr";
  2. forward-confirm — прямой резолв каждого PTR-имени содержит исходный IP;
  3. перекрёстная сверка с именами хостов проекта, резолвящимися в этот IP.

Неподтверждённые PTR-имена сохраняются с confirmed=False: PTR контролируется
владельцем адреса, а не владельцем имени, поэтому без forward-confirm имя —
это подсказка, а не факт. Потребитель решает, что с ним делать (IpFarmService
подшивает адрес к существующему хосту только по подтверждённому имени).

Про таймауты: у socket.gethostbyaddr нет параметра таймаута, а
socket.setdefaulttimeout глобален на процесс и отравил бы все сокеты
приложения. Поэтому каждый вызов обёрнут в asyncio.wait_for. Оговорка: поток
при таймауте не отменяется и доживает до ответа резолвера — их число
ограничено семафором.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field

from app.config import get_settings
from app.netguard import is_disallowed_ip

settings = get_settings()

# Провенанс имени: PTR-запись адреса либо имя уже известного в проекте хоста.
SOURCE_PTR = "ptr"
SOURCE_PROJECT = "project"
_SOURCE_RANK = {SOURCE_PTR: 0, SOURCE_PROJECT: 1}


@dataclass
class ResolvedHost:
    ip: str | None  # первичный адрес — по нему идёт пробив
    ips: list[str] = field(default_factory=list)  # все адреса; ips[0] == ip
    blocked: bool = False  # резолв в приватный/запрещённый IP при внешнем-only режиме
    error: str | None = None


@dataclass
class ResolvedName:
    hostname: str
    source: str  # SOURCE_PTR | SOURCE_PROJECT
    confirmed: bool = False  # прямой резолв имени возвращает этот IP

    def as_dict(self) -> dict:
        return {"hostname": self.hostname, "source": self.source, "confirmed": self.confirmed}


@dataclass
class ReverseResult:
    ip: str
    names: list[ResolvedName] = field(default_factory=list)
    error: str | None = None


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def order_addrs(infos: list) -> list[str]:
    """Все адреса из getaddrinfo без дублей: сначала IPv4, затем IPv6.

    Порядок значим — первый адрес становится primary у хоста, а IPv4 остаётся
    предпочтительным для пробива (как и в исходной _pick_addr).
    """
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    ordered = v4 + v6 if (v4 or v6) else [i[4][0] for i in infos]
    return list(dict.fromkeys(ordered))


def pick_addr(infos: list) -> str | None:
    addrs = order_addrs(infos)
    return addrs[0] if addrs else None


async def _getaddrinfo(host: str, timeout: float | None = None) -> list:
    coro = asyncio.to_thread(socket.getaddrinfo, host, None)
    if timeout is None:
        return await coro
    return await asyncio.wait_for(coro, timeout)


async def resolve_forward(hostnames: list[str]) -> dict[str, ResolvedHost]:
    """Резолвит имена в адреса. IP-литералы не резолвятся, но проходят SSRF-гейт."""
    sem = asyncio.Semaphore(settings.farm_max_concurrency)
    allow_private = settings.farm_allow_private_targets

    async def resolve_one(host: str) -> tuple[str, ResolvedHost]:
        literal = is_ip_literal(host)
        async with sem:
            if literal:
                addrs = [host]
            else:
                try:
                    infos = await _getaddrinfo(host)
                except (socket.gaierror, TimeoutError):
                    return host, ResolvedHost(ip=None, error=f"{host}: DNS не разрешается")
                addrs = order_addrs(infos)
        if not addrs:
            return host, ResolvedHost(ip=None, error=f"{host}: DNS не разрешается")
        addr = addrs[0]
        if not allow_private and is_disallowed_ip(addr):
            return host, ResolvedHost(
                ip=addr, ips=addrs, blocked=True, error=f"{host} → внутренний IP {addr}: пробив пропущен"
            )
        return host, ResolvedHost(ip=addr, ips=addrs)

    return dict(await asyncio.gather(*(resolve_one(h) for h in hostnames)))


def merge_names(names: list[ResolvedName]) -> list[ResolvedName]:
    """Дедуп по имени: confirmed = OR, приоритет source — ptr над project.

    Сортировка: подтверждённые выше, затем PTR над project, затем по алфавиту —
    чтобы в UI первым шло самое достоверное имя.
    """
    merged: dict[str, ResolvedName] = {}
    for name in names:
        current = merged.get(name.hostname)
        if current is None:
            merged[name.hostname] = ResolvedName(name.hostname, name.source, name.confirmed)
            continue
        current.confirmed = current.confirmed or name.confirmed
        if _SOURCE_RANK[name.source] < _SOURCE_RANK[current.source]:
            current.source = name.source
    return sorted(
        merged.values(),
        key=lambda n: (not n.confirmed, _SOURCE_RANK[n.source], n.hostname),
    )


async def reverse_resolve(ips: list[str], project_hostnames: list[str]) -> dict[str, ReverseResult]:
    """Определяет, в какие имена резолвится каждый IP (PTR + сверка с проектом)."""
    results = {ip: ReverseResult(ip=ip) for ip in ips}
    if not settings.farm_reverse_dns_enabled or not ips:
        return results

    sem = asyncio.Semaphore(settings.farm_max_concurrency)
    timeout = settings.farm_reverse_dns_timeout_seconds

    async def addrs_of(hostname: str) -> set[str]:
        """Прямой резолв имени; при любой ошибке — пустое множество."""
        async with sem:
            try:
                infos = await _getaddrinfo(hostname, timeout)
            except (socket.gaierror, socket.herror, TimeoutError, OSError):
                return set()
        return set(order_addrs(infos))

    async def ptr_names(ip: str) -> tuple[list[str], str | None]:
        async with sem:
            try:
                primary, aliases, _ = await asyncio.wait_for(
                    asyncio.to_thread(socket.gethostbyaddr, ip), timeout
                )
            except (socket.herror, socket.gaierror, TimeoutError, OSError):
                return [], None
        names = [n.lower().rstrip(".") for n in [primary, *aliases] if n]
        return list(dict.fromkeys(names)), None

    # Фаза A: PTR для каждого адреса.
    ptr_by_ip = dict(zip(ips, await asyncio.gather(*(ptr_names(ip) for ip in ips)), strict=True))

    # Фаза B: прямой резолв всех кандидатов — PTR-имён и имён проекта — одним пулом,
    # чтобы одно и то же имя не резолвилось дважды.
    candidates = {name for names, _ in ptr_by_ip.values() for name in names}
    candidates.update(h.lower().rstrip(".") for h in project_hostnames if h)
    candidate_list = sorted(candidates)
    forward = dict(zip(candidate_list, await asyncio.gather(*(addrs_of(h) for h in candidate_list)), strict=True))

    project_set = {h.lower().rstrip(".") for h in project_hostnames if h}
    for ip in ips:
        names, error = ptr_by_ip[ip]
        collected = [
            ResolvedName(hostname=name, source=SOURCE_PTR, confirmed=ip in forward.get(name, set()))
            for name in names
        ]
        # Имя уже известного в проекте хоста, резолвящееся в этот адрес, подтверждено
        # по построению — мы только что видели его A/AAAA-запись. Дубли с PTR
        # схлопнет merge_names (ptr имеет приоритет по source).
        collected.extend(
            ResolvedName(hostname=name, source=SOURCE_PROJECT, confirmed=True)
            for name in project_set
            if ip in forward.get(name, set())
        )
        results[ip] = ReverseResult(ip=ip, names=merge_names(collected), error=error)
    return results
