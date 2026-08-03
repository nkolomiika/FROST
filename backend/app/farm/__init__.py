"""Рекон-ферма: серверный пробив вставленных списков хостов и IP.

Отдельный сервис (задел на самостоятельный проект). Фазы строго разделены,
и только последняя трогает БД:

  1. core.parse_targets      — чистая функция: нормализация + дедуп.
  2. resolver.resolve_forward — getaddrinfo в потоке; внешний-only гейт.
     resolver.reverse_resolve — PTR + forward-confirm + сверка с проектом.
  3. core.probe_candidates   — httpx-фан-аут, БД НЕ трогает.
  4. hosts._persist / ips._persist_ips — последовательно, коммит на элемент.

Правило корректности: async-сессию нельзя входить конкурентно. Фазы 1–3 не
касаются БД; только фаза записи (последовательный `for`) её ждёт. Никогда не
складывать запрос к БД внутрь probe-gather.

Раскладка модулей:
  core.py     — разбор целей, SSRF-transport, HTTP-пробив
  resolver.py — прямой и обратный DNS
  hosts.py    — HostFarmService
  ips.py      — IpFarmService
  jobs.py     — постановка в очередь и прогон задач

Чистые предикаты адреса лежат уровнем выше и переиспользуются вне фермы:
app.netguard.is_disallowed_ip (SSRF) и app.cloudflare.is_cloudflare_ip.
"""

from app.cloudflare import is_cloudflare_ip
from app.farm.core import (
    HTTPS_PORTS,
    TOP_WEB_PORTS,
    ParsedTarget,
    ProbeCandidate,
    ProbeResult,
    ProbeTransport,
    parse_targets,
)
from app.farm.hosts import HostFarmService
from app.farm.ips import IpFarmService
from app.farm.js import JsFarmService
from app.farm.portscan import PortScanFarmService
from app.farm.reverse import ReverseFarmService
from app.farm.subs import SubdomainFarmService
from app.farm.jobs import enqueue_job, run_recon_job
from app.farm.resolver import (
    ResolvedHost,
    ResolvedName,
    ReverseResult,
    resolve_forward,
    reverse_resolve,
)

__all__ = [
    "HTTPS_PORTS",
    "TOP_WEB_PORTS",
    "HostFarmService",
    "IpFarmService",
    "JsFarmService",
    "PortScanFarmService",
    "ReverseFarmService",
    "SubdomainFarmService",
    "ParsedTarget",
    "ProbeCandidate",
    "ProbeResult",
    "ProbeTransport",
    "ResolvedHost",
    "ResolvedName",
    "ReverseResult",
    "enqueue_job",
    "is_cloudflare_ip",
    "parse_targets",
    "resolve_forward",
    "reverse_resolve",
    "run_recon_job",
]
