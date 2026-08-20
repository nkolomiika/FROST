"""Внутренний sidecar генерации Word-отчётов (интерим Go-миграции).

Go-API собирает данные проекта (sqlc + MinIO) и шлёт их сюда JSON'ом; sidecar
реконструирует доменные объекты и переиспользует проверенный `word_builder`
(build_szi/build_pp) и статические помощники `ReportService` — байт-в-байт та же
вёрстка сертификационных .docx, без переписывания OOXML-логики.

Запуск (в образе backend, есть все зависимости и шаблоны):
    uvicorn app.report_sidecar:app --host 0.0.0.0 --port 8100

Сеть только внутренняя (docker), аутентификация — общий секрет REPORTS_SIDECAR_TOKEN
(если задан). Наружу не публикуется.
"""
from __future__ import annotations

import base64
import os
import re
from datetime import date
from io import BytesIO
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Response
from PIL import Image as PillowImage
from PIL import ImageOps
from PIL import UnidentifiedImageError

from app.enums import AssetType, CvssVersion, Severity, VulnerabilityStatus
from app.reports.word_builder import build_pp, build_szi

# Помощники реплицированы из app.services (тот же код), чтобы sidecar не тянул
# весь services.py и его зависимости (cvss/yaml/...).
_STEP_MARKER_RE = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s*")


def _split_steps_text(text: str) -> list[str]:
    lines = [line.strip() for line in text.replace("\r", "").split("\n")]
    steps: list[str] = []
    for line in lines:
        if not line:
            continue
        stripped = _STEP_MARKER_RE.sub("", line).strip()
        if not stripped:
            continue
        if steps and stripped == line:
            steps[-1] = f"{steps[-1]}\n{stripped}"
        else:
            steps.append(stripped)
    return steps


def _hydrate_workflow_steps(vuln) -> None:
    if vuln.workflow_steps is not None:
        return
    vuln.workflow_steps = [
        {"id": str(uuid4()), "description": description, "image_file_ids": []}
        for description in _split_steps_text(vuln.steps_to_reproduce or "")
    ]


def _normalize_report_image_bytes(image_bytes: bytes) -> bytes | None:
    try:
        with PillowImage.open(BytesIO(image_bytes)) as image:
            normalized = ImageOps.exif_transpose(image)
            output = BytesIO()
            save_image = normalized.convert("RGBA") if normalized.mode in {"P", "LA"} else normalized
            save_format = "PNG" if "A" in save_image.getbands() else "JPEG"
            if save_format == "JPEG":
                save_image = save_image.convert("RGB")
                save_image.save(output, format=save_format, quality=90)
            else:
                save_image.save(output, format=save_format)
            return output.getvalue()
    except (UnidentifiedImageError, OSError, ValueError):
        return None


def _build_report_indexes(data: dict) -> dict:
    hosts = data["hosts"]
    ports = data["ports"]
    vulnerability_assets = data["vulnerability_assets"]
    files = data["files"]
    host_by_id = {host.id: host for host in hosts}
    ports_by_host_id: dict[int, list] = {}
    for port in ports:
        ports_by_host_id.setdefault(port.host_id, []).append(port)
    assets_by_vuln_id: dict[int, list] = {}
    for asset in vulnerability_assets:
        assets_by_vuln_id.setdefault(asset.vulnerability_id, []).append(asset)
    files_by_vuln_id: dict[int, list] = {}
    for file_meta in files:
        files_by_vuln_id.setdefault(file_meta.vulnerability_id, []).append(file_meta)
    files_by_id = {file_meta.id: file_meta for file_meta in files}
    severity_stats: dict[str, int] = {}
    status_stats: dict[str, int] = {}
    for vuln in data["vulnerabilities"]:
        severity_stats[vuln.severity.value] = severity_stats.get(vuln.severity.value, 0) + 1
        status_stats[vuln.status.value] = status_stats.get(vuln.status.value, 0) + 1
    return {
        "host_by_id": host_by_id,
        "ports_by_host_id": ports_by_host_id,
        "assets_by_vuln_id": assets_by_vuln_id,
        "files_by_vuln_id": files_by_vuln_id,
        "files_by_id": files_by_id,
        "severity_stats": severity_stats,
        "status_stats": status_stats,
    }

app = FastAPI(title="FROST report sidecar", docs_url=None, redoc_url=None, openapi_url=None)

_TOKEN = os.getenv("REPORTS_SIDECAR_TOKEN", "")


def _parse_date(value: Any) -> date | None:
    if not value:
        return None
    return date.fromisoformat(str(value)[:10])


def _enum_by_name(enum_cls, value):
    """Маппит строковое DB-имя (UPPERCASE член) в член enum; None → None."""
    if value is None:
        return None
    try:
        return enum_cls[str(value)]
    except KeyError:
        # запасной путь: по значению
        return enum_cls(str(value))


def _build_objects(payload: dict) -> tuple[dict, dict[int, bytes]]:
    p = payload["project"]
    project = SimpleNamespace(
        id=p.get("id"),
        name=p.get("name") or "",
        start_date=_parse_date(p.get("start_date")),
        end_date=_parse_date(p.get("end_date")),
    )
    hosts = [
        SimpleNamespace(id=h["id"], hostname=h.get("hostname"), ip_address=h.get("ip_address"))
        for h in (payload.get("hosts") or [])
    ]
    ports = [SimpleNamespace(**pt) for pt in (payload.get("ports") or [])]
    vulnerabilities = []
    for v in (payload.get("vulnerabilities") or []):
        vulnerabilities.append(
            SimpleNamespace(
                id=v["id"],
                title=v.get("title") or "",
                severity=_enum_by_name(Severity, v.get("severity")) or Severity.INFO,
                cvss_version=_enum_by_name(CvssVersion, v.get("cvss_version")),
                cvss_vector=v.get("cvss_vector"),
                cvss_score=v.get("cvss_score"),
                cwe_id=v.get("cwe_id"),
                description=v.get("description"),
                impact=v.get("impact"),
                recommendations=v.get("recommendations"),
                steps_to_reproduce=v.get("steps_to_reproduce"),
                workflow_steps=v.get("workflow_steps"),
                status=_enum_by_name(VulnerabilityStatus, v.get("status")) or VulnerabilityStatus.OPEN,
                created_by=v.get("created_by"),
            )
        )
    assets = [
        SimpleNamespace(
            id=a.get("id"),
            vulnerability_id=a["vulnerability_id"],
            asset_type=_enum_by_name(AssetType, a.get("asset_type")),
            asset_id=a["asset_id"],
        )
        for a in (payload.get("assets") or [])
    ]
    files = [
        SimpleNamespace(
            id=f["id"],
            vulnerability_id=f["vulnerability_id"],
            content_type=f.get("content_type") or "application/octet-stream",
            original_name=f.get("original_name") or "",
        )
        for f in (payload.get("files") or [])
    ]
    data = {
        "project": project,
        "members": (payload.get("members") or []),
        "vulnerabilities": vulnerabilities,
        "hosts": hosts,
        "ports": ports,
        "host_ids": [h.id for h in hosts],
        "vulnerability_assets": assets,
        "files": files,
    }
    # Нормализация картинок (тот же код, что в ReportService).
    raw_images: dict[str, str] = payload.get("images") or {}
    image_bytes_by_id: dict[int, bytes] = {}
    for f in files:
        if not f.content_type.startswith("image/"):
            continue
        b64 = raw_images.get(str(f.id))
        if not b64:
            continue
        try:
            raw = base64.b64decode(b64)
        except Exception:
            continue
        normalized = _normalize_report_image_bytes(raw)
        if normalized:
            image_bytes_by_id[f.id] = normalized
    return data, image_bytes_by_id


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/render/{kind}")
def render(kind: str, payload: dict, x_sidecar_token: str = Header(default="")) -> Response:
    if _TOKEN and x_sidecar_token != _TOKEN:
        raise HTTPException(status_code=401, detail="bad sidecar token")
    if kind not in ("szi", "pp"):
        raise HTTPException(status_code=422, detail="unknown report kind")

    data, image_bytes_by_id = _build_objects(payload)
    for vuln in data["vulnerabilities"]:
        _hydrate_workflow_steps(vuln)
    indexes = _build_report_indexes(data)
    builder = build_szi if kind == "szi" else build_pp
    content = builder(data, indexes, image_bytes_by_id)
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
