from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from io import BytesIO
from typing import Literal
from urllib.parse import parse_qsl, urlparse, urlsplit
from uuid import uuid4

import ipaddress
import socket

import magic
import httpx
import yaml
from cvss import CVSS4
from fastapi import UploadFile
from PIL import Image as PillowImage, ImageOps, UnidentifiedImageError
from sqlalchemy import Select, and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.orm.attributes import set_committed_value

from app.cloudflare import is_cloudflare_ip
from app.config import get_settings
from app.enums import (
    AssetType,
    NotificationType,
    ProjectRole,
    ProjectStatus,
    Severity,
    UserRole,
    VulnerabilityStatus,
)
from app.reports import ReportKind, build_pp, build_szi
from app.exceptions import ConflictError, ForbiddenError, NotFoundError, UnauthorizedError, ValidationError
from app.models import (
    AccountReactivationToken,
    AgentApiToken,
    AgentApiTokenProjectGrant,
    AuditLog,
    Comment,
    CommentMention,
    Endpoint,
    File,
    Host,
    HostIpAddress,
    Invitation,
    JiraInstance,
    JiraIssueLink,
    JsFile,
    MailJob,
    Notification,
    PasswordResetToken,
    Port,
    Project,
    ProjectCredential,
    ProjectFolder,
    ProjectHiddenIp,
    ProjectJiraLink,
    ProjectMember,
    ProjectNote,
    ProjectNoteComment,
    RefreshToken,
    Service,
    User,
    Vulnerability,
    VulnerabilityAsset,
)
from app.mail import (
    build_invitation_email,
    build_password_reset_email,
    build_reactivation_email,
    build_temporary_password_email,
)
from app.messaging import publish_mail_job
from app.netguard import is_disallowed_ip
from app.schemas import (
    CommentOut,
    ImportResult,
    MentionOut,
    NotificationContext,
    NotificationOut,
    OpenApiImportResult,
    PcfImportPayload,
    ProjectNoteCommentOut,
)
from app.security import (
    TWO_FA_PENDING_TYPE,
    create_2fa_pending_token,
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    generate_invitation_token,
    generate_password_reset_token,
    generate_reactivation_token,
    generate_totp_secret,
    hash_agent_token,
    hash_invitation_token,
    hash_password,
    hash_password_reset_token,
    hash_reactivation_token,
    hash_refresh_token,
    totp_provisioning_uri,
    totp_qr_png_data_url,
    verify_password,
    verify_totp,
)
from app.storage.minio_client import MinioStorage
from app.ws_manager import ws_manager

settings = get_settings()
MENTION_RE = re.compile(r"@([a-zA-Z0-9_.-]{1,100})")
MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_OPENAPI_IMPORT_BYTES = 2 * 1024 * 1024
MAX_OPENAPI_PATHS = 2000
ALLOWED_MIME_TYPES = {
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "text/plain",
    "application/pdf",
    "application/xml",
    "application/json",
    "application/zip",
    "application/x-tar",
    "application/gzip",
}


def _sanitize_filename(raw: str | None, fallback: str = "file.bin") -> str:
    """Удаляет path separators, null-bytes и control-chars из оригинального имени файла."""
    if not raw:
        return fallback
    import os

    name = os.path.basename(str(raw).replace("\\", "/")).strip()
    name = "".join(ch for ch in name if ch.isprintable() and ch not in {"\x00"})
    name = name.lstrip(".")  # запрещаем "../" и скрытые имена .git/.env
    return name or fallback


class AuditService:
    """Сервис записи журнала действий."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def log(
        self,
        action: str,
        *,
        user_id: int | None = None,
        entity_type: str | None = None,
        entity_id: int | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Создаёт запись аудита (хранится в Postgres-таблице audit_logs)."""
        created_at = datetime.now(UTC)
        self.db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=details,
                ip_address=ip_address,
                created_at=created_at,
            )
        )
        await self.db.commit()


class AgentTokenService:
    """Управляет bearer-токенами для AI agent API."""

    DEFAULT_SCOPES = ["projects:read", "assets:read", "vulns:read", "notes:read"]
    # Полный набор прав, которые распознаёт /api/v2 (см. require_agent_scope).
    # Токен не может нести право вне этого набора — это единственный источник
    # истины по scopes и для бэкенда, и для фронта.
    ALLOWED_SCOPES = ["projects:read", "assets:read", "vulns:read", "vulns:write", "notes:read", "notes:write"]

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _member_project_ids(self, user_id: int) -> set[int]:
        """Проекты, где пользователь состоит участником (для не-админа = его доступ)."""
        rows = await self.db.scalars(select(ProjectMember.project_id).where(ProjectMember.user_id == user_id))
        return set(rows.all())

    async def _project_ids_for_token(self, token_id: int) -> list[int]:
        rows = await self.db.scalars(
            select(AgentApiTokenProjectGrant.project_id).where(AgentApiTokenProjectGrant.token_id == token_id)
        )
        return list(rows.all())

    @staticmethod
    def _serialize_token(token: AgentApiToken, project_ids: list[int]) -> dict:
        """Сериализует AgentApiToken в dict со всеми полями (включая nullable, отсутствующие в __dict__)."""
        return {
            "id": token.id,
            "name": token.name,
            "token_prefix": token.token_prefix,
            "scopes": token.scopes or [],
            "all_projects": token.all_projects,
            "created_by": token.created_by,
            "expires_at": token.expires_at,
            "revoked_at": token.revoked_at,
            "last_used_at": token.last_used_at,
            "created_at": token.created_at,
            "updated_at": token.updated_at,
            "project_ids": project_ids,
        }

    async def list_tokens(self, actor_id: int) -> list[dict]:
        """Токены, выпущенные этим пользователем (каждый видит только свои)."""
        tokens = (
            await self.db.scalars(
                select(AgentApiToken)
                .where(AgentApiToken.created_by == actor_id)
                .order_by(AgentApiToken.created_at.desc())
            )
        ).all()
        result: list[dict] = []
        for token in tokens:
            result.append(self._serialize_token(token, await self._project_ids_for_token(token.id)))
        return result

    async def create_token(self, payload: dict, actor: User) -> tuple[dict, str]:
        # 1. Scopes: только валидные и только те, что выбрал пользователь — токен
        #    не получает прав, которых не запрашивали.
        requested_scopes = list(dict.fromkeys(payload.get("scopes") or []))
        unknown = [s for s in requested_scopes if s not in self.ALLOWED_SCOPES]
        if unknown:
            raise ValidationError(f"Неизвестные scope: {', '.join(unknown)}")
        scopes = requested_scopes or list(self.DEFAULT_SCOPES)

        # 2. Срок действия — не в прошлом (пусто = бессрочный токен).
        expires_at = payload.get("expires_at")
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise ValidationError("Срок действия токена уже истёк")

        # 3. Проекты: токен не может дать доступ шире, чем у самого создателя.
        #    Админ видит все проекты, поэтому может выдать на любые / all_projects.
        #    Не-админу all_projects означает «все МОИ проекты» и дополнительно
        #    ограничивается на запросе (require_agent_project_access) его текущим
        #    членством; явный список проверяется здесь по членству.
        is_admin = actor.role == UserRole.ADMIN
        all_projects = bool(payload.get("all_projects"))
        project_ids = list(dict.fromkeys(payload.get("project_ids") or []))
        if not all_projects and not is_admin:
            allowed = await self._member_project_ids(actor.id)
            forbidden = [pid for pid in project_ids if pid not in allowed]
            if forbidden:
                raise ForbiddenError(
                    f"Нет доступа к проектам: {', '.join(map(str, forbidden))} — токен не может превышать ваши права"
                )

        raw_token = f"storm_{secrets.token_urlsafe(32)}"
        token = AgentApiToken(
            name=payload["name"],
            token_hash=hash_agent_token(raw_token),
            token_prefix=raw_token[:14],
            scopes=scopes,
            all_projects=all_projects,
            created_by=actor.id,
            expires_at=expires_at,
        )
        self.db.add(token)
        await self.db.flush()
        if not all_projects:
            for project_id in project_ids:
                self.db.add(AgentApiTokenProjectGrant(token_id=token.id, project_id=project_id))
        await self.db.commit()
        await self.db.refresh(token)
        await self.audit.log("CREATE", user_id=actor.id, entity_type="agent_api_token", entity_id=token.id)
        return self._serialize_token(token, await self._project_ids_for_token(token.id)), raw_token

    async def revoke_token(self, token_id: int, actor: User) -> None:
        token = await self.db.scalar(select(AgentApiToken).where(AgentApiToken.id == token_id))
        if not token:
            raise NotFoundError("Agent API token не найден")
        # Владелец удаляет только свои токены; админ — любые.
        if actor.role != UserRole.ADMIN and token.created_by != actor.id:
            raise ForbiddenError("Можно удалять только свои токены")
        # Физически удаляем токен: пользователь нажимает «удалить» и ожидает,
        # что запись исчезнет из списка. Grants подчищаются по ON DELETE CASCADE.
        await self.db.delete(token)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor.id, entity_type="agent_api_token", entity_id=token_id)


@dataclass
class JiraCredentials:
    """Разрешённые параметры подключения к Jira (из env или БД)."""

    base_url: str
    email: str
    token: str
    issue_type: str
    enabled: bool
    default_project_key: str = ""
    start_date_field: str = ""
    due_in_days: int = 14


class _SafeJiraTransport(httpx.AsyncHTTPTransport):
    """httpx transport с защитой от DNS rebinding.

    Между нашей валидацией Jira base_url (в момент save config) и реальным
    HTTP-запросом проходит время, за которое атакующий с контролем DNS
    жертвы мог бы сменить запись с публичного IP на 127.0.0.1 / RFC1918
    (короткий TTL). Этот transport повторно резолвит host прямо перед
    отправкой и валит запрос, если в свежем DNS-ответе есть запрещённый IP.

    NB: это не «pin-by-IP» в чистом виде — между нашим getaddrinfo и
    getaddrinfo внутри httpcore остаётся миллисекундное окно. Но оно сводит
    практическую атаку к нулю и не требует ломать SNI / TLS verification.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host:
            try:
                resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
            except socket.gaierror as exc:
                raise httpx.ConnectError(f"DNS не разрешает {host}: {exc}") from exc
            for addr in resolved:
                if JiraIntegrationService._is_disallowed_ip(addr):
                    raise httpx.ConnectError(
                        f"DNS вернул запрещённый IP {addr} для {host} — отклонено защитой SSRF"
                    )
        return await super().handle_async_request(request)


class JiraIntegrationService:
    """Backend-only интеграция с Jira REST API."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    # Сам предикат живёт в app.netguard — им пользуется и рекон-ферма, которой
    # нельзя тянуть за собой весь app.services.
    _is_disallowed_ip = staticmethod(is_disallowed_ip)

    @classmethod
    def _validate_external_url(cls, raw_url: str) -> str:
        """SSRF-защита: разрешаем только https и публичные хосты (запрет на localhost, RFC1918, link-local)."""
        if not raw_url or not raw_url.strip():
            raise ValidationError("Jira base_url не может быть пустым")
        parsed = urlparse(raw_url.strip())
        if parsed.scheme not in {"https", "http"}:
            raise ValidationError("Jira base_url должен использовать https:// или http://")
        if parsed.scheme == "http" and not settings.debug:
            raise ValidationError("Jira base_url в production должен использовать https://")
        host = parsed.hostname
        if not host:
            raise ValidationError("Jira base_url не содержит host")
        if host.lower() in {"localhost", "metadata.google.internal", "instance-data"}:
            raise ValidationError("Jira base_url указывает на запрещённый хост")
        try:
            resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror as exc:
            raise ValidationError(f"Не удалось разрешить host Jira: {exc}") from exc
        for addr in resolved:
            if cls._is_disallowed_ip(addr):
                raise ValidationError("Jira base_url указывает на внутренний/приватный IP — запрещено")
        return raw_url.strip().rstrip("/")

    @staticmethod
    def _fernet():
        from cryptography.fernet import Fernet

        settings = get_settings()
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.jwt_secret_key.encode("utf-8")).digest())
        return Fernet(key)

    @classmethod
    def _encrypt_secret(cls, value: str) -> str:
        return cls._fernet().encrypt(value.encode("utf-8")).decode("utf-8")

    @classmethod
    def _decrypt_secret(cls, value: str) -> str:
        return cls._fernet().decrypt(value.encode("utf-8")).decode("utf-8")

    async def get_config(self) -> JiraInstance | None:
        return await self.db.scalar(select(JiraInstance).order_by(JiraInstance.created_at.desc()))

    async def resolve_credentials(self) -> "JiraCredentials | None":
        """Возвращает рабочие креды Jira: сперва из env (деплой-конфиг), иначе из БД.

        Интеграция задаётся один раз на уровне деплоя (JIRA_* в окружении) и не
        настраивается через веб. Ветка с БД оставлена для обратной совместимости.
        """
        s = get_settings()
        if s.jira_configured:
            return JiraCredentials(
                base_url=s.jira_base_url,
                email=s.jira_email,
                token=s.jira_api_token,
                issue_type=s.jira_default_issue_type or "Task",
                enabled=s.jira_enabled,
                default_project_key=(s.jira_default_project_key or "").upper(),
                start_date_field=s.jira_start_date_field,
                due_in_days=s.jira_due_in_days,
            )
        cfg = await self.get_config()
        if cfg:
            return JiraCredentials(
                base_url=cfg.base_url,
                email=cfg.email,
                token=self._decrypt_secret(cfg.api_token_encrypted),
                issue_type=cfg.default_issue_type,
                enabled=cfg.is_enabled,
                default_project_key=(s.jira_default_project_key or "").upper(),
                start_date_field=s.jira_start_date_field,
                due_in_days=s.jira_due_in_days,
            )
        return None

    async def upsert_config(self, payload: dict, actor_id: int) -> JiraInstance:
        config = await self.get_config()
        token = payload.pop("api_token", None)
        if not config:
            if not token:
                raise ValidationError("Для первой настройки Jira нужен api_token")
            safe_base_url = self._validate_external_url(payload["base_url"])
            config = JiraInstance(
                name=payload["name"],
                base_url=safe_base_url,
                email=payload["email"],
                api_token_encrypted=self._encrypt_secret(token),
                default_issue_type=payload["default_issue_type"],
                is_enabled=payload["is_enabled"],
                created_by=actor_id,
            )
            self.db.add(config)
        else:
            for key, value in payload.items():
                if key == "base_url" and value:
                    value = self._validate_external_url(value)
                if value is not None:
                    setattr(config, key, value)
            if token:
                config.api_token_encrypted = self._encrypt_secret(token)
        await self.db.commit()
        await self.db.refresh(config)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="jira_config", entity_id=config.id)
        return config

    async def upsert_project_link(self, project_id: int, jira_project_key: str, actor_id: int) -> ProjectJiraLink:
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        link = await self.db.scalar(select(ProjectJiraLink).where(ProjectJiraLink.project_id == project_id))
        if not link:
            link = ProjectJiraLink(project_id=project_id, jira_project_key=jira_project_key.upper(), created_by=actor_id)
            self.db.add(link)
        else:
            link.jira_project_key = jira_project_key.upper()
        await self.db.commit()
        await self.db.refresh(link)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="project_jira_link", entity_id=link.id)
        return link

    async def get_project_link(self, project_id: int) -> ProjectJiraLink | None:
        return await self.db.scalar(select(ProjectJiraLink).where(ProjectJiraLink.project_id == project_id))

    # Критичность в задаче показываем по-русски — интерфейс Jira русский.
    SEVERITY_RU = {
        "critical": "Критическая",
        "high": "Высокая",
        "medium": "Средняя",
        "low": "Низкая",
        "info": "Информационная",
    }

    @staticmethod
    def _jira_doc(sections: list[tuple[str, str | None, str]]) -> dict:
        """Собирает ADF-описание с заголовками: на каждую секцию — h3 и тело.

        sections — тройки (заголовок, текст, стиль), где стиль:
        "text" — каждая строка становится абзацем,
        "ordered" — нумерованный список, каждая строка = пункт (собственная
        нумерация в исходном тексте снимается, чтобы не задваивалась).
        Пустые секции пропускаются.
        """
        content: list[dict] = []
        for title, body, style in sections:
            text = (body or "").strip()
            if not text:
                continue
            content.append({"type": "heading", "attrs": {"level": 3}, "content": [{"type": "text", "text": title}]})
            lines = [line.strip() for line in text[:8000].split("\n") if line.strip()]
            if style == "ordered":
                items = []
                for line in lines:
                    clean = re.sub(r"^\s*(?:\d+[.)]|[-*•])\s*", "", line)
                    if clean:
                        items.append(
                            {"type": "listItem", "content": [{"type": "paragraph", "content": [{"type": "text", "text": clean}]}]}
                        )
                if items:
                    content.append({"type": "orderedList", "attrs": {"order": 1}, "content": items})
            else:
                for line in lines:
                    content.append({"type": "paragraph", "content": [{"type": "text", "text": line}]})
        if not content:
            content = [{"type": "paragraph", "content": [{"type": "text", "text": "—"}]}]
        return {"type": "doc", "version": 1, "content": content}

    async def get_issue_link(self, vulnerability_id: int) -> JiraIssueLink | None:
        return await self.db.scalar(select(JiraIssueLink).where(JiraIssueLink.vulnerability_id == vulnerability_id))

    async def _claim_issue_link(self, vuln_id: int) -> tuple[JiraIssueLink, bool]:
        """Бронирует JiraIssueLink с status='pending' перед HTTP-вызовом.

        Возвращает (link, created). Если параллельный запрос уже забронировал
        запись — отдаём существующую и created=False. UNIQUE constraint на
        vulnerability_id гарантирует, что один из конкурентов проиграет
        IntegrityError'ом — это и есть точка сериализации.
        """
        link = JiraIssueLink(
            vulnerability_id=vuln_id,
            jira_issue_key="",
            jira_issue_url="",
            status="pending",
        )
        self.db.add(link)
        try:
            await self.db.commit()
        except IntegrityError:
            await self.db.rollback()
            existing = await self.get_issue_link(vuln_id)
            if existing is None:
                # Теоретически возможно, если race-конкурент откатился после
                # нашего fail'а — сообщаем явно, чтобы клиент повторил.
                raise ValidationError("Не удалось создать связь с Jira, повторите попытку")
            return existing, False
        await self.db.refresh(link)
        return link, True

    async def _mark_link_error(self, link: JiraIssueLink, error: str) -> None:
        """Отмечает связь как «error» и сохраняет последнюю ошибку для UI."""
        link.status = "error"
        link.last_error = error[:500]
        await self.db.commit()

    async def export_vulnerability(self, project_id: int, vuln_id: int, actor_id: int) -> JiraIssueLink:
        config = await self.resolve_credentials()
        if not config or not config.enabled:
            raise ValidationError("Jira не настроена или отключена")
        # Ключ Jira-проекта: единый на уровне деплоя (JIRA_DEFAULT_PROJECT_KEY),
        # либо явная привязка проекта (если задана), если дефолта нет.
        link_row = await self.get_project_link(project_id)
        project_key = config.default_project_key or (link_row.jira_project_key if link_row else "")
        if not project_key:
            raise ValidationError("Не задан Jira project key (JIRA_DEFAULT_PROJECT_KEY)")

        # 1) Проверяем готовый линк — если он уже «linked», возвращаем как есть.
        existing = await self.get_issue_link(vuln_id)
        if existing and existing.status == "linked":
            return existing

        # 2) Бронируем запись (claim-row) ДО HTTP-вызова. Защита от race:
        #    два параллельных POST не смогут оба создать issue в Jira —
        #    один проиграет на UNIQUE constraint и получит существующий линк.
        if existing is None:
            link, created = await self._claim_issue_link(vuln_id)
            if not created and link.status == "linked":
                return link
        else:
            # Линк был в pending/error — переиспользуем для retry.
            link = existing
            link.status = "pending"
            link.last_error = None
            await self.db.commit()

        vuln_data = await VulnerabilityService(self.db).get(project_id, vuln_id)
        vulnerability = vuln_data["vulnerability"]
        today = datetime.now(UTC).date()
        due = today + timedelta(days=config.due_in_days)
        # Описание — структурированное: каждый блок со своим заголовком (даты
        # вынесены в поля Jira, поэтому в тексте их не дублируем).
        cvss = f"{vulnerability.cvss_score or ''} {vulnerability.cvss_vector or ''}".strip()
        sections: list[tuple[str, str | None, str]] = [
            ("Описание", vulnerability.description, "text"),
            ("Критичность", self.SEVERITY_RU.get(vulnerability.severity.value, vulnerability.severity.value), "text"),
            ("CVSS", cvss, "text"),
            ("Шаги воспроизведения", vulnerability.steps_to_reproduce, "ordered"),
            ("Влияние на систему", vulnerability.impact, "text"),
            ("Рекомендации к устранению", vulnerability.recommendations, "text"),
        ]
        # Summary формата "STORM-{id уязвимости} — {название}"; задача создаётся
        # в статусе To Do (первый статус workflow Jira по умолчанию).
        summary = f"STORM-{vuln_id} — {vulnerability.title}"
        fields = {
            "project": {"key": project_key},
            "summary": summary[:250],
            "issuetype": {"name": config.issue_type},
            "description": self._jira_doc(sections),
            # Дата начала = сегодня, срок выполнения = сегодня + N дней (Jira ждёт YYYY-MM-DD).
            "duedate": due.isoformat(),
        }
        if config.start_date_field:
            fields[config.start_date_field] = today.isoformat()
        payload = {"fields": fields}
        safe_base_url = self._validate_external_url(config.base_url)

        # 3) Сетевой вызов с обёрткой ошибок и DNS-rebind защитой.
        try:
            async with httpx.AsyncClient(
                timeout=20.0,
                follow_redirects=False,
                transport=_SafeJiraTransport(),
            ) as client:
                response = await client.post(
                    f"{safe_base_url}/rest/api/3/issue",
                    json=payload,
                    auth=(config.email, config.token),
                )
        except httpx.HTTPError as exc:
            await self._mark_link_error(link, f"Jira недоступна: {exc.__class__.__name__}: {exc}")
            raise ValidationError(f"Jira недоступна: {exc}") from exc

        if response.status_code >= 400:
            error_text = response.text[:500]
            await self._mark_link_error(link, f"HTTP {response.status_code}: {error_text}")
            raise ValidationError(f"Jira вернула ошибку {response.status_code}: {error_text}")

        try:
            data = response.json()
        except ValueError as exc:
            await self._mark_link_error(link, "Jira вернула не-JSON ответ")
            raise ValidationError("Jira вернула не-JSON ответ") from exc

        issue_key = data.get("key")
        if not issue_key:
            await self._mark_link_error(link, "Jira не вернула key созданной issue")
            raise ValidationError("Jira не вернула key созданной issue")

        link.jira_issue_key = issue_key
        link.jira_issue_url = f"{safe_base_url}/browse/{issue_key}"
        link.status = "linked"
        link.last_error = None
        await self.db.commit()
        await self.db.refresh(link)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="jira_issue_link", entity_id=link.id)
        return link


@dataclass
class LoginOutcome:
    """Результат первого шага логина.

    requires_2fa=True — пароль верный, но у пользователя включён TOTP: полноценная
    сессия не выдаётся, вместо этого — короткоживущий pending_token до ввода кода.
    """

    user: User
    requires_2fa: bool
    access_token: str | None = None
    refresh_token: str | None = None
    pending_token: str | None = None


class AuthService:
    """Сервис аутентификации и управления JWT-cookie."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _issue_session(self, user_id: int) -> tuple[str, str]:
        """Создаёт пару access/refresh токенов и сохраняет refresh в БД."""
        access_token = create_access_token(user_id)
        refresh_token = create_refresh_token(user_id)
        refresh_hash = hash_refresh_token(refresh_token)
        expires_at = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
        self.db.add(RefreshToken(user_id=user_id, token_hash=refresh_hash, expires_at=expires_at))
        await self.db.commit()
        return access_token, refresh_token

    async def issue_session_for_user(self, user_id: int) -> tuple[str, str]:
        """Выдаёт сессию без проверки пароля — для активации приглашения (пароль только что задан)."""
        return await self._issue_session(user_id)

    async def login(self, username: str, password: str, ip_address: str | None = None) -> LoginOutcome:
        """Проверяет учётные данные. При включённом 2FA возвращает challenge вместо сессии."""
        user = await self.db.scalar(select(User).where(User.username == username))
        if not user or not verify_password(password, user.password_hash):
            raise UnauthorizedError("Неверный логин или пароль")
        if not user.is_active or user.is_locked:
            raise UnauthorizedError("Пользователь деактивирован")

        if user.totp_enabled:
            pending_token = create_2fa_pending_token(user.id)
            await self.audit.log("LOGIN_2FA_CHALLENGE", user_id=user.id, ip_address=ip_address)
            return LoginOutcome(user=user, requires_2fa=True, pending_token=pending_token)

        access_token, refresh_token = await self._issue_session(user.id)
        await self.audit.log("LOGIN", user_id=user.id, ip_address=ip_address)
        return LoginOutcome(user=user, requires_2fa=False, access_token=access_token, refresh_token=refresh_token)

    async def verify_2fa(self, pending_token: str | None, code: str, ip_address: str | None = None) -> tuple[str, str, User]:
        """Завершает вход: сверяет TOTP-код по pending-токену и выдаёт сессию."""
        if not pending_token:
            raise UnauthorizedError("Сессия подтверждения истекла — войдите заново")
        user_id = decode_token(pending_token, expected_type=TWO_FA_PENDING_TYPE)
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user or not user.is_active or user.is_locked:
            raise UnauthorizedError("Пользователь не найден или деактивирован")
        if not user.totp_enabled or not user.totp_secret:
            raise UnauthorizedError("Двухфакторная аутентификация не настроена")
        if not verify_totp(decrypt_secret(user.totp_secret), code):
            raise UnauthorizedError("Неверный код подтверждения")

        access_token, refresh_token = await self._issue_session(user.id)
        await self.audit.log("LOGIN", user_id=user.id, ip_address=ip_address, details={"twofa": True})
        return access_token, refresh_token, user

    async def refresh(self, refresh_token: str | None, ip_address: str | None = None) -> tuple[str, str]:
        """Обновляет access-токен по валидному refresh-cookie с ротацией refresh-токена.

        Возвращает (new_access_token, new_refresh_token).
        Старый refresh-токен помечается как revoked. Если приходит уже отозванный токен —
        отзываем все активные токены пользователя как защиту от token reuse / replay-атаки.
        """
        if not refresh_token:
            raise UnauthorizedError("Refresh token отсутствует")
        user_id = decode_token(refresh_token, expected_type="refresh")
        token_hash = hash_refresh_token(refresh_token)
        existing = await self.db.scalar(
            select(RefreshToken).where(
                and_(
                    RefreshToken.token_hash == token_hash,
                    RefreshToken.user_id == user_id,
                )
            )
        )
        now = datetime.now(UTC)
        if existing and existing.revoked_at is not None:
            # Replay attempt: revoke all active tokens for this user
            await self.db.execute(
                update(RefreshToken)
                .where(and_(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)))
                .values(revoked_at=now)
            )
            await self.db.commit()
            await self.audit.log("LOGOUT", user_id=user_id, ip_address=ip_address, details={"reason": "refresh_token_replay"})
            raise UnauthorizedError("Refresh token уже использован")
        if not existing or existing.expires_at <= now:
            raise UnauthorizedError("Refresh token недействителен")
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user or not user.is_active or user.is_locked:
            raise UnauthorizedError("Пользователь деактивирован")
        existing.revoked_at = now
        new_access = create_access_token(user_id)
        new_refresh = create_refresh_token(user_id)
        new_expires_at = now + timedelta(days=settings.jwt_refresh_token_expire_days)
        self.db.add(RefreshToken(user_id=user_id, token_hash=hash_refresh_token(new_refresh), expires_at=new_expires_at))
        await self.db.commit()
        return new_access, new_refresh

    async def logout(self, user_id: int, ip_address: str | None = None) -> None:
        """Отзывает все активные refresh-токены пользователя."""
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("LOGOUT", user_id=user_id, ip_address=ip_address)


class UserService:
    """Сервис управления пользователями."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.storage = MinioStorage()
        self.storage.ensure_bucket()

    @staticmethod
    def _normalized_admin_email() -> str:
        configured_email = settings.initial_admin_email
        if "@" in configured_email and "." in configured_email.split("@", 1)[1]:
            return configured_email
        return "admin@example.com"

    @staticmethod
    def _generate_temporary_password() -> str:
        return secrets.token_urlsafe(12)

    @staticmethod
    def _ensure_mail_delivery_enabled() -> None:
        if not settings.mail_enabled:
            raise ValidationError("Отправка email отключена. Включите SMTP/mail worker или задайте пароль вручную.")

    @staticmethod
    def ensure_can_view_avatar(requester: User, target_user_id: int) -> None:
        if requester.role != UserRole.ADMIN and requester.id != target_user_id:
            raise ForbiddenError("Недостаточно прав для просмотра чужого аватара")

    async def _ensure_unique_identity(
        self,
        *,
        username: str | None = None,
        email: str | None = None,
        exclude_user_id: int | None = None,
    ) -> None:
        clauses = []
        if username:
            clauses.append(User.username == username)
        if email:
            clauses.append(User.email == email)
        if not clauses:
            return
        query = select(User).where(or_(*clauses))
        if exclude_user_id:
            query = query.where(User.id != exclude_user_id)
        exists = await self.db.scalar(query)
        if exists:
            raise ConflictError("Username or email is already taken")

    async def _enqueue_temporary_password_mail(
        self,
        *,
        user: User,
        temporary_password: str,
        actor_id: int | None,
    ) -> MailJob:
        subject, body, html = build_temporary_password_email(
            username=user.full_name or user.username, temporary_password=temporary_password
        )
        job = MailJob(
            user_id=user.id,
            created_by=actor_id,
            recipient_email=user.email,
            subject=subject,
            template="temporary_password",
            payload={"username": user.username, "temporary_password": temporary_password, "body": body, "html": html},
            status="pending",
        )
        self.db.add(job)
        await self.db.flush()
        return job

    async def _publish_mail_job(self, job: MailJob) -> None:
        try:
            await publish_mail_job(job.id)
        except Exception as exc:
            job.status = "pending"
            job.last_error = str(exc)
        else:
            job.status = "queued"
            job.published_at = datetime.now(UTC)
        await self.db.commit()

    async def get_user_profile(self, user_id: int) -> User:
        return await self.get_user(user_id)

    async def bootstrap_admin(self) -> None:
        """Создаёт стартового администратора при пустой таблице users."""
        normalized_email = self._normalized_admin_email()
        existing_admin = await self.db.scalar(
            select(User).where(or_(User.username == settings.initial_admin_username, User.email == normalized_email))
        )
        if existing_admin:
            if existing_admin.username == settings.initial_admin_username and existing_admin.email != normalized_email:
                existing_admin.email = normalized_email
                await self.db.commit()
            return
        total_users = await self.db.scalar(select(func.count()).select_from(User))
        if total_users and total_users > 0:
            admin_user = await self.db.scalar(select(User).where(User.username == settings.initial_admin_username))
            if admin_user and ("@" not in admin_user.email or "." not in admin_user.email.split("@", 1)[1]):
                admin_user.email = normalized_email
                await self.db.commit()
            return
        admin = User(
            username=settings.initial_admin_username,
            email=normalized_email,
            full_name="Administrator",
            password_hash=hash_password(settings.initial_admin_password),
            password_changed_at=datetime.now(UTC),
            role=UserRole.ADMIN,
            is_active=True,
        )
        self.db.add(admin)
        await self.db.commit()

    async def list_users(self, page: int, size: int) -> tuple[list[User], int]:
        """Возвращает список пользователей с пагинацией."""
        total = await self.db.scalar(select(func.count()).select_from(User)) or 0
        items = (
            await self.db.scalars(select(User).order_by(User.created_at.desc()).offset((page - 1) * size).limit(size))
        ).all()
        return list(items), total

    async def get_user(self, user_id: int) -> User:
        """Возвращает пользователя по идентификатору."""
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user:
            raise NotFoundError("User not found")
        return user

    async def create_user(self, payload: dict, actor_id: int, ip_address: str | None = None) -> User:
        """Создаёт нового пользователя."""
        await self._ensure_unique_identity(username=payload["username"], email=payload["email"])
        send_invite_email = bool(payload.get("send_invite_email"))
        temporary_password = payload.get("password")
        if send_invite_email:
            self._ensure_mail_delivery_enabled()
        if not temporary_password and not send_invite_email:
            raise ValidationError("Provide a password or enable sending an email invitation")
        if not temporary_password:
            temporary_password = self._generate_temporary_password()
        user = User(
            username=payload["username"],
            email=payload["email"],
            full_name=payload.get("full_name"),
            password_hash=hash_password(temporary_password),
            password_changed_at=datetime.now(UTC),
            role=payload.get("role", UserRole.PENTESTER),
            project_role=payload.get("project_role", ProjectRole.PENTESTER),
            is_active=True,
        )
        self.db.add(user)
        mail_job: MailJob | None = None
        if send_invite_email:
            await self.db.flush()
            mail_job = await self._enqueue_temporary_password_mail(user=user, temporary_password=temporary_password, actor_id=actor_id)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="user",
            entity_id=user.id,
            details={"email": user.email, "invite_sent": send_invite_email},
            ip_address=ip_address,
        )
        if mail_job:
            await self._publish_mail_job(mail_job)
        return user

    # ------------------------------------------------------------------
    # Приглашения (invite-flow): админ зовёт по email, пользователь сам
    # задаёт username+пароль по ссылке из письма. До активации записи в
    # users нет, поэтому вход невозможен — обычная ошибка логина.
    # ------------------------------------------------------------------
    async def _enqueue_invitation_mail(self, *, invitation: Invitation, raw_token: str, actor_id: int | None) -> MailJob:
        activation_url = f"{settings.app_base_url.rstrip('/')}/activate?token={raw_token}"
        subject, body, html = build_invitation_email(
            recipient_email=invitation.email,
            full_name=invitation.full_name,
            activation_url=activation_url,
        )
        job = MailJob(
            user_id=None,
            created_by=actor_id,
            recipient_email=invitation.email,
            subject=subject,
            template="invitation",
            payload={"invitation_id": invitation.id, "activation_url": activation_url, "body": body, "html": html},
            status="pending",
        )
        self.db.add(job)
        await self.db.flush()
        return job

    async def create_invitation(self, payload: dict, actor_id: int, ip_address: str | None = None) -> tuple[Invitation, MailJob]:
        """Создаёт приглашение и ставит письмо со ссылкой активации в очередь."""
        self._ensure_mail_delivery_enabled()
        email = payload["email"]
        existing_user = await self.db.scalar(select(User).where(User.email == email))
        if existing_user:
            raise ConflictError("A user with this email already exists")
        now = datetime.now(UTC)
        active_invite = await self.db.scalar(
            select(Invitation).where(
                and_(Invitation.email == email, Invitation.status == "pending", Invitation.expires_at > now)
            )
        )
        if active_invite:
            raise ConflictError("Приглашение для этого email уже отправлено — используйте повторную отправку")
        raw_token = generate_invitation_token()
        invitation = Invitation(
            email=email,
            full_name=payload.get("full_name"),
            role=payload.get("role", UserRole.PENTESTER),
            project_role=payload.get("project_role", ProjectRole.PENTESTER),
            token_hash=hash_invitation_token(raw_token),
            status="pending",
            expires_at=now + timedelta(hours=settings.invite_token_expire_hours),
            invited_by=actor_id,
        )
        self.db.add(invitation)
        await self.db.flush()
        mail_job = await self._enqueue_invitation_mail(invitation=invitation, raw_token=raw_token, actor_id=actor_id)
        await self.db.commit()
        await self.db.refresh(invitation)
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="invitation",
            entity_id=invitation.id,
            details={"email": email},
            ip_address=ip_address,
        )
        await self._publish_mail_job(mail_job)
        return invitation, mail_job

    async def list_invitations(self) -> list[Invitation]:
        """Незавершённые приглашения (pending, в т.ч. истёкшие) для админ-панели."""
        items = (
            await self.db.scalars(
                select(Invitation).where(Invitation.status == "pending").order_by(Invitation.created_at.desc())
            )
        ).all()
        return list(items)

    async def _get_invitation(self, invitation_id: int) -> Invitation:
        invitation = await self.db.scalar(select(Invitation).where(Invitation.id == invitation_id))
        if not invitation:
            raise NotFoundError("Приглашение не найдено")
        return invitation

    async def resend_invitation(self, invitation_id: int, actor_id: int, ip_address: str | None = None) -> tuple[Invitation, MailJob]:
        """Перевыпускает токен приглашения, продлевает срок и снова шлёт письмо."""
        self._ensure_mail_delivery_enabled()
        invitation = await self._get_invitation(invitation_id)
        if invitation.status == "accepted":
            raise ConflictError("Приглашение уже принято")
        raw_token = generate_invitation_token()
        invitation.token_hash = hash_invitation_token(raw_token)
        invitation.status = "pending"
        invitation.expires_at = datetime.now(UTC) + timedelta(hours=settings.invite_token_expire_hours)
        mail_job = await self._enqueue_invitation_mail(invitation=invitation, raw_token=raw_token, actor_id=actor_id)
        await self.db.commit()
        await self.db.refresh(invitation)
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="invitation_resend",
            entity_id=invitation.id,
            details={"email": invitation.email},
            ip_address=ip_address,
        )
        await self._publish_mail_job(mail_job)
        return invitation, mail_job

    async def revoke_invitation(self, invitation_id: int, actor_id: int, ip_address: str | None = None) -> None:
        """Отзывает приглашение — ссылка перестаёт работать."""
        invitation = await self._get_invitation(invitation_id)
        if invitation.status == "accepted":
            raise ConflictError("Приглашение уже принято — отозвать нельзя")
        invitation.status = "revoked"
        await self.db.commit()
        await self.audit.log(
            "DELETE",
            user_id=actor_id,
            entity_type="invitation",
            entity_id=invitation_id,
            details={"email": invitation.email},
            ip_address=ip_address,
        )

    async def _load_invitation_by_token(self, raw_token: str) -> Invitation | None:
        return await self.db.scalar(select(Invitation).where(Invitation.token_hash == hash_invitation_token(raw_token)))

    async def get_invitation_info(self, raw_token: str) -> dict:
        """Публичные данные для страницы активации (email/имя) или причина отказа."""
        invitation = await self._load_invitation_by_token(raw_token)
        # revoked/несуществующий токен намеренно неразличимы — не раскрываем факт отзыва.
        if not invitation or invitation.status == "revoked":
            return {"valid": False, "reason": "not_found"}
        if invitation.status == "accepted":
            return {"valid": False, "reason": "used"}
        if invitation.is_expired:
            return {"valid": False, "reason": "expired"}
        return {"valid": True, "email": invitation.email, "full_name": invitation.full_name}

    async def check_invitation_username_available(self, raw_token: str, username: str) -> bool:
        """Проверяет свободен ли username. Требует валидного токена (без открытой энумерации)."""
        invitation = await self._load_invitation_by_token(raw_token)
        if not invitation or invitation.status != "pending" or invitation.is_expired:
            raise UnauthorizedError("Приглашение недействительно или истекло")
        existing = await self.db.scalar(select(User).where(User.username == username))
        return existing is None

    async def accept_invitation(self, raw_token: str, username: str, password: str, ip_address: str | None = None) -> User:
        """Активация: приглашённый задаёт username+пароль, создаётся пользователь."""
        invitation = await self._load_invitation_by_token(raw_token)
        if not invitation or invitation.status != "pending" or invitation.is_expired:
            raise UnauthorizedError("Приглашение недействительно или истекло")
        # Гонка: username/email могли занять между проверкой доступности и отправкой.
        await self._ensure_unique_identity(username=username, email=invitation.email)
        user = User(
            username=username,
            email=invitation.email,
            full_name=invitation.full_name,
            password_hash=hash_password(password),
            password_changed_at=datetime.now(UTC),
            role=invitation.role,
            project_role=invitation.project_role,
            is_active=True,
        )
        self.db.add(user)
        await self.db.flush()
        invitation.status = "accepted"
        invitation.accepted_at = datetime.now(UTC)
        invitation.accepted_user_id = user.id
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log(
            "CREATE",
            user_id=user.id,
            entity_type="user",
            entity_id=user.id,
            details={"via": "invitation", "invitation_id": invitation.id},
            ip_address=ip_address,
        )
        return user

    # ------------------------------------------------------------------
    # Восстановление пароля («забыли пароль»)
    # ------------------------------------------------------------------
    async def _enqueue_password_reset_mail(self, *, user: User, raw_token: str) -> MailJob:
        reset_url = f"{settings.app_base_url.rstrip('/')}/reset-password?token={raw_token}"
        subject, body, html = build_password_reset_email(
            username=user.full_name or user.username,
            reset_url=reset_url,
            expire_hours=settings.password_reset_expire_hours,
        )
        job = MailJob(
            user_id=user.id,
            created_by=None,
            recipient_email=user.email,
            subject=subject,
            template="password_reset",
            payload={"reset_url": reset_url, "body": body, "html": html},
            status="pending",
        )
        self.db.add(job)
        await self.db.flush()
        return job

    async def request_password_reset(self, email: str, ip_address: str | None = None) -> None:
        """Отправляет ссылку восстановления, если такой пользователь есть.

        Ничего не возвращает и не бросает при отсутствии пользователя: иначе
        форма «забыли пароль» стала бы оракулом для перебора существующих email.
        """
        self._ensure_mail_delivery_enabled()
        user = await self.db.scalar(select(User).where(User.email == email))
        if not user or not user.is_active or user.is_locked:
            await self.audit.log(
                "UPDATE",
                user_id=None,
                entity_type="password_reset_requested_unknown",
                details={"email": email},
                ip_address=ip_address,
            )
            return

        # Прежние неиспользованные ссылки гасим: активной остаётся только последняя.
        await self.db.execute(
            update(PasswordResetToken)
            .where(and_(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)))
            .values(used_at=datetime.now(UTC))
        )
        raw_token = generate_password_reset_token()
        self.db.add(
            PasswordResetToken(
                user_id=user.id,
                token_hash=hash_password_reset_token(raw_token),
                expires_at=datetime.now(UTC) + timedelta(hours=settings.password_reset_expire_hours),
            )
        )
        mail_job = await self._enqueue_password_reset_mail(user=user, raw_token=raw_token)
        await self.db.commit()
        await self.audit.log(
            "UPDATE",
            user_id=user.id,
            entity_type="password_reset_requested",
            entity_id=user.id,
            ip_address=ip_address,
        )
        await self._publish_mail_job(mail_job)

    async def _load_reset_token(self, raw_token: str) -> PasswordResetToken | None:
        return await self.db.scalar(
            select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_password_reset_token(raw_token))
        )

    async def get_password_reset_info(self, raw_token: str) -> dict:
        """Проверяет ссылку до показа формы нового пароля."""
        token = await self._load_reset_token(raw_token)
        if not token:
            return {"valid": False, "reason": "not_found"}
        if token.used_at is not None:
            return {"valid": False, "reason": "used"}
        if not token.is_usable:
            return {"valid": False, "reason": "expired"}
        user = await self.db.scalar(select(User).where(User.id == token.user_id))
        if not user or not user.is_active or user.is_locked:
            return {"valid": False, "reason": "not_found"}
        return {"valid": True, "username": user.username}

    async def confirm_password_reset(self, raw_token: str, new_password: str, ip_address: str | None = None) -> User:
        """Ставит новый пароль по одноразовой ссылке и гасит все сессии."""
        token = await self._load_reset_token(raw_token)
        if not token or not token.is_usable:
            raise UnauthorizedError("Ссылка недействительна или истекла")
        user = await self.db.scalar(select(User).where(User.id == token.user_id))
        if not user or not user.is_active or user.is_locked:
            raise UnauthorizedError("Ссылка недействительна или истекла")

        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)
        token.used_at = datetime.now(UTC)
        # В отличие от отключения 2FA, здесь сессии сбрасываем намеренно: пароль
        # меняют в том числе когда доступ мог быть скомпрометирован.
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log(
            "UPDATE",
            user_id=user.id,
            entity_type="password_reset_completed",
            entity_id=user.id,
            ip_address=ip_address,
        )
        return user

    # ------------------------------------------------------------------
    # Возврат деактивированного пользователя (мягкое удаление -> is_locked).
    # Админ жмёт «вернуть» -> письмо со ссылкой; пользователь переходит по ней
    # -> аккаунт разблокируется и сразу выдаётся сессия (см. auth-роутер).
    # ------------------------------------------------------------------
    async def _enqueue_reactivation_mail(self, *, user: User, raw_token: str) -> MailJob:
        reactivate_url = f"{settings.app_base_url.rstrip('/')}/reactivate?token={raw_token}"
        subject, body, html = build_reactivation_email(
            username=user.full_name or user.username,
            reactivate_url=reactivate_url,
            expire_hours=settings.reactivation_expire_hours,
        )
        job = MailJob(
            user_id=user.id,
            created_by=None,
            recipient_email=user.email,
            subject=subject,
            template="reactivation",
            payload={"reactivate_url": reactivate_url, "body": body, "html": html},
            status="pending",
        )
        self.db.add(job)
        await self.db.flush()
        return job

    async def request_reactivation(self, user_id: int, actor_id: int, ip_address: str | None = None) -> MailJob:
        """Админ возвращает деактивированного пользователя: шлём ссылку-возврат.

        Аккаунт остаётся заблокированным — доступ вернётся, только когда пользователь
        сам перейдёт по ссылке из письма (там же сразу выдаётся сессия).
        """
        self._ensure_mail_delivery_enabled()
        user = await self.get_user(user_id)
        if not user.is_locked:
            raise ValidationError("The user is not deactivated")
        # Прежние неиспользованные ссылки гасим: активной остаётся только последняя.
        await self.db.execute(
            update(AccountReactivationToken)
            .where(and_(AccountReactivationToken.user_id == user.id, AccountReactivationToken.used_at.is_(None)))
            .values(used_at=datetime.now(UTC))
        )
        raw_token = generate_reactivation_token()
        self.db.add(
            AccountReactivationToken(
                user_id=user.id,
                token_hash=hash_reactivation_token(raw_token),
                expires_at=datetime.now(UTC) + timedelta(hours=settings.reactivation_expire_hours),
            )
        )
        mail_job = await self._enqueue_reactivation_mail(user=user, raw_token=raw_token)
        await self.db.commit()
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="user_reactivation_requested",
            entity_id=user.id,
            details={"email": user.email},
            ip_address=ip_address,
        )
        await self._publish_mail_job(mail_job)
        return mail_job

    async def _load_reactivation_token(self, raw_token: str) -> AccountReactivationToken | None:
        return await self.db.scalar(
            select(AccountReactivationToken).where(
                AccountReactivationToken.token_hash == hash_reactivation_token(raw_token)
            )
        )

    async def get_reactivation_info(self, raw_token: str) -> dict:
        """Публичная проверка ссылки-возврата до показа кнопки входа."""
        token = await self._load_reactivation_token(raw_token)
        if not token:
            return {"valid": False, "reason": "not_found"}
        if token.used_at is not None:
            return {"valid": False, "reason": "used"}
        if not token.is_usable:
            return {"valid": False, "reason": "expired"}
        user = await self.db.scalar(select(User).where(User.id == token.user_id))
        # Аккаунт мог уже разблокировать другой способ — тогда ссылка не нужна.
        if not user or not user.is_active or not user.is_locked:
            return {"valid": False, "reason": "not_found"}
        return {"valid": True, "username": user.username}

    async def complete_reactivation(self, raw_token: str, ip_address: str | None = None) -> User:
        """Разблокирует аккаунт по одноразовой ссылке и возвращает пользователя
        (сессию выдаёт auth-роутер поверх этого)."""
        token = await self._load_reactivation_token(raw_token)
        if not token or not token.is_usable:
            raise UnauthorizedError("Ссылка недействительна или истекла")
        user = await self.db.scalar(select(User).where(User.id == token.user_id))
        if not user or not user.is_active:
            raise UnauthorizedError("Ссылка недействительна или истекла")
        user.is_locked = False
        token.used_at = datetime.now(UTC)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log(
            "UPDATE",
            user_id=user.id,
            entity_type="user_reactivated",
            entity_id=user.id,
            ip_address=ip_address,
        )
        return user

    async def update_user(self, user_id: int, payload: dict, actor_id: int, ip_address: str | None = None) -> User:
        """Обновляет данные пользователя."""
        user = await self.get_user(user_id)
        submitted_email = payload.pop("email", None)
        if submitted_email is not None and submitted_email != user.email:
            raise ValidationError("An admin can't change a user's email — the user must change it themselves")
        # Юзернейм неизменяем — даже админом: на него завязаны логин, упоминания и
        # история действий, поэтому его правку не принимаем (как и email).
        submitted_username = payload.pop("username", None)
        if submitted_username is not None and submitted_username != user.username:
            raise ValidationError("The username can't be changed — it's tied to the user")
        await self._ensure_unique_identity(username=user.username, email=user.email, exclude_user_id=user.id)
        for key, value in payload.items():
            if value is not None:
                setattr(user, key, value)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="user", entity_id=user.id, ip_address=ip_address)
        return user

    async def update_own_profile(self, user_id: int, payload: dict, ip_address: str | None = None) -> User:
        user = await self.get_user(user_id)
        username = payload.get("username", user.username)
        email = payload.get("email", user.email)
        await self._ensure_unique_identity(username=username, email=email, exclude_user_id=user.id)
        for key, value in payload.items():
            if value is not None:
                setattr(user, key, value)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log("UPDATE", user_id=user_id, entity_type="user_profile", entity_id=user.id, ip_address=ip_address)
        return user

    async def delete_user(self, user_id: int, actor_id: int, ip_address: str | None = None) -> None:
        """«Удаляет» пользователя — на деле деактивирует (мягкое удаление).

        Строку не стираем: за пользователем тянутся его проекты, находки, заметки и
        т.п. с FK RESTRICT — реальный DELETE упирался бы в них и падал 500. Вместо
        этого выставляем is_locked, чтобы вход был закрыт (см. get_current_user и
        login), и отзываем активные refresh-токены, чтобы блокировка сработала сразу.
        Всё авторство и связи при этом сохраняются.
        """
        if user_id == actor_id:
            raise ValidationError("You can't block yourself")
        user = await self.get_user(user_id)
        user.is_locked = True
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="user", entity_id=user_id, ip_address=ip_address)

    async def reset_password(self, user_id: int, actor_id: int, ip_address: str | None = None) -> User:
        """Сбрасывает пароль пользователя, выставляет временный пароль и отправляет его по почте."""
        self._ensure_mail_delivery_enabled()
        user = await self.get_user(user_id)
        temporary_password = self._generate_temporary_password()
        user.password_hash = hash_password(temporary_password)
        user.password_changed_at = None
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        mail_job = await self._enqueue_temporary_password_mail(user=user, temporary_password=temporary_password, actor_id=actor_id)
        await self.db.commit()
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="user_password_reset",
            entity_id=user_id,
            details={"email": user.email},
            ip_address=ip_address,
        )
        await self._publish_mail_job(mail_job)
        return user

    async def change_own_password(
        self,
        user_id: int,
        *,
        current_password: str,
        new_password: str,
        ip_address: str | None = None,
    ) -> User:
        user = await self.get_user(user_id)
        if not verify_password(current_password, user.password_hash):
            raise UnauthorizedError("Текущий пароль указан неверно")
        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=user.id, entity_type="user_password", entity_id=user.id, ip_address=ip_address)
        await self.db.refresh(user)
        return user

    async def setup_2fa(self, user_id: int, ip_address: str | None = None) -> tuple[str, str, str]:
        """Готовит привязку TOTP: генерирует секрет (хранит зашифрованным, но пока не
        включает) и возвращает (secret, otpauth_uri, qr_png_data_url)."""
        user = await self.get_user(user_id)
        if user.totp_enabled:
            raise ValidationError("Двухфакторная аутентификация уже включена")
        secret = generate_totp_secret()
        user.totp_secret = encrypt_secret(secret)
        user.totp_confirmed_at = None
        await self.db.commit()
        otpauth_uri = totp_provisioning_uri(secret, user.username)
        return secret, otpauth_uri, totp_qr_png_data_url(otpauth_uri)

    async def confirm_2fa(self, user_id: int, code: str, ip_address: str | None = None) -> User:
        """Включает 2FA после проверки первого кода из приложения-аутентификатора."""
        user = await self.get_user(user_id)
        if user.totp_enabled:
            raise ValidationError("Двухфакторная аутентификация уже включена")
        if not user.totp_secret:
            raise ValidationError("Сначала запросите настройку 2FA")
        if not verify_totp(decrypt_secret(user.totp_secret), code):
            raise ValidationError("Неверный код из приложения-аутентификатора")
        user.totp_enabled = True
        user.totp_confirmed_at = datetime.now(UTC)
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=user.id, entity_type="user_2fa_enabled", entity_id=user.id, ip_address=ip_address)
        await self.db.refresh(user)
        return user

    async def disable_2fa(self, user_id: int, password: str, ip_address: str | None = None) -> User:
        """Отключает 2FA (требует пароль аккаунта). Активные сессии не сбрасываем —
        отключение второго фактора не должно разлогинивать пользователя."""
        user = await self.get_user(user_id)
        if not verify_password(password, user.password_hash):
            raise UnauthorizedError("Пароль указан неверно")
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_confirmed_at = None
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=user.id, entity_type="user_2fa_disabled", entity_id=user.id, ip_address=ip_address)
        await self.db.refresh(user)
        return user

    async def admin_reset_2fa(self, user_id: int, actor_id: int, ip_address: str | None = None) -> User:
        """Сбрасывает 2FA пользователю от имени администратора (потеря телефона)."""
        user = await self.get_user(user_id)
        user.totp_enabled = False
        user.totp_secret = None
        user.totp_confirmed_at = None
        await self.db.execute(
            update(RefreshToken)
            .where(and_(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None)))
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="user_2fa_reset", entity_id=user_id, ip_address=ip_address)
        await self.db.refresh(user)
        return user

    async def upload_avatar(self, user_id: int, upload: UploadFile, ip_address: str | None = None) -> User:
        user = await self.get_user(user_id)
        content = await upload.read()
        if len(content) > 5 * 1024 * 1024:
            raise ValidationError("Размер аватара превышает 5 МБ")
        mime_type = magic.from_buffer(content, mime=True)
        if mime_type not in {"image/png", "image/jpeg", "image/webp", "image/gif"}:
            raise ValidationError("Аватар должен быть изображением PNG, JPEG, WEBP или GIF")
        if user.avatar_minio_key:
            await asyncio.to_thread(self.storage.delete, user.avatar_minio_key)
        safe_name = _sanitize_filename(upload.filename, fallback="avatar.bin")
        object_key = await asyncio.to_thread(self.storage.upload_bytes, content, mime_type, safe_name)
        user.avatar_minio_bucket = settings.minio_bucket_name
        user.avatar_minio_key = object_key
        user.avatar_content_type = mime_type
        user.avatar_uploaded_at = datetime.now(UTC)
        await self.db.commit()
        await self.db.refresh(user)
        await self.audit.log("FILE_UPLOAD", user_id=user.id, entity_type="user_avatar", entity_id=user.id, ip_address=ip_address)
        return user

    async def download_avatar(self, user_id: int) -> tuple[User, bytes]:
        user = await self.get_user(user_id)
        if not user.avatar_minio_key:
            raise NotFoundError("Аватар не найден")
        blob = await asyncio.to_thread(self.storage.download_bytes, user.avatar_minio_key)
        return user, blob


class ProjectService:
    """Сервис управления проектами и участниками."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    @staticmethod
    def _validate_project_dates(start_date: date | None, end_date: date | None) -> None:
        if start_date and end_date and end_date < start_date:
            raise ValidationError("Дата окончания проекта не может быть раньше даты начала")

    @staticmethod
    def _normalize_project_folder(folder: str | None) -> str:
        normalized = (folder or "").strip()
        return normalized

    @staticmethod
    def _normalize_folder_segment(name: str) -> str:
        normalized = name.strip().strip("/")
        if not normalized:
            raise ValidationError("Название папки не может быть пустым")
        if "/" in normalized:
            raise ValidationError("Название папки не должно содержать '/'")
        return normalized

    async def list_projects(self, current_user: User, page: int, size: int, status: str | None = None) -> tuple[list[Project], int]:
        """Возвращает список проектов с учётом доступа."""
        query: Select = select(Project)
        if status:
            query = query.where(Project.status == status)
        if current_user.role != UserRole.ADMIN:
            query = query.join(ProjectMember, ProjectMember.project_id == Project.id).where(ProjectMember.user_id == current_user.id)
        count_query = select(func.count()).select_from(query.subquery())
        total = await self.db.scalar(count_query) or 0
        items = (await self.db.scalars(query.order_by(Project.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        return list(items), total

    async def get_project(self, project_id: int) -> Project:
        """Возвращает проект по ID."""
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        return project

    async def create_project(self, payload: dict, actor_id: int, ip_address: str | None = None) -> Project:
        """Создаёт новый проект."""
        self._validate_project_dates(payload.get("start_date"), payload.get("end_date"))
        payload["folder"] = self._normalize_project_folder(payload.get("folder"))
        project = Project(**payload, created_by=actor_id)
        self.db.add(project)
        await self.db.commit()
        await self.db.refresh(project)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="project", entity_id=project.id, ip_address=ip_address)
        await ws_manager.broadcast_projects_index(
            {"event": "created", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}}
        )
        return project

    async def update_project(self, project_id: int, payload: dict, actor_id: int, ip_address: str | None = None) -> Project:
        """Обновляет проект."""
        project = await self.get_project(project_id)
        if "folder" in payload:
            payload["folder"] = self._normalize_project_folder(payload.get("folder"))
        next_start_date = payload.get("start_date", project.start_date)
        next_end_date = payload.get("end_date", project.end_date)
        self._validate_project_dates(next_start_date, next_end_date)
        old_status = project.status
        next_status = payload.get("status")
        if next_status is not None:
            if next_status == ProjectStatus.ACTIVE:
                payload["timeline_frozen_at"] = None
            elif old_status == ProjectStatus.ACTIVE:
                payload["timeline_frozen_at"] = datetime.now(UTC)
            elif "timeline_frozen_at" not in payload:
                payload["timeline_frozen_at"] = project.timeline_frozen_at
        for key, value in payload.items():
            if value is not None:
                setattr(project, key, value)
            elif key == "timeline_frozen_at":
                setattr(project, key, None)
        await self.db.commit()
        await self.db.refresh(project)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="project", entity_id=project.id, ip_address=ip_address)
        await ws_manager.broadcast(project.id, {"event": "updated", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}})
        await ws_manager.broadcast_projects_index(
            {"event": "updated", "entity": "project", "project_id": str(project.id), "data": {"id": str(project.id)}}
        )
        if payload.get("status") and payload["status"] != old_status:
            await self.audit.log(
                "STATUS_CHANGE",
                user_id=actor_id,
                entity_type="project",
                entity_id=project.id,
                details={"old_status": old_status.value, "new_status": project.status.value},
                ip_address=ip_address,
            )
            await self._notify_project_status_changed(project, actor_id)
        return project

    async def _notify_project_status_changed(self, project: Project, actor_id: int) -> None:
        """Повод №4: статус проекта изменился — сообщаем его участникам.

        Кроме того, кто менял: он и так знает.
        """
        member_ids = list(
            (await self.db.scalars(select(ProjectMember.user_id).where(ProjectMember.project_id == project.id))).all()
        )
        recipients = [uid for uid in member_ids if uid != actor_id]
        if not recipients:
            return
        status_value = getattr(project.status, "value", project.status)
        for user_id in recipients:
            self.db.add(
                Notification(
                    user_id=user_id,
                    type=NotificationType.PROJECT_STATUS_CHANGED,
                    project_id=project.id,
                    actor_id=actor_id,
                    status=status_value,
                    is_read=False,
                )
            )
        await self.db.commit()
        for user_id in recipients:
            await ws_manager.notify_user(
                user_id,
                {
                    "event": "notification",
                    "entity": "notification",
                    "data": {
                        "type": NotificationType.PROJECT_STATUS_CHANGED.value,
                        "is_read": False,
                        "project_id": str(project.id),
                        "status": status_value,
                    },
                },
            )

    async def delete_project(self, project_id: int, actor_id: int, ip_address: str | None = None) -> None:
        """Удаляет проект и связанные сущности."""
        project = await self.get_project(project_id)
        await self.db.delete(project)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="project", entity_id=project_id, ip_address=ip_address)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "project", "project_id": str(project_id), "data": {"id": str(project_id)}})
        await ws_manager.broadcast_projects_index(
            {"event": "deleted", "entity": "project", "project_id": str(project_id), "data": {"id": str(project_id)}}
        )

    async def list_project_stats(self, current_user: User) -> list[dict]:
        """Счётчики по каждому доступному проекту одним запросом.

        Возвращает hosts_count / open_findings / total_findings + статус, чтобы
        UI мог агрегировать по вкладке (активные/архивные) без N+1 запросов.
        Видимость та же, что и у списка проектов: не-админ видит только свои.
        """
        hosts_sq = (
            select(Host.project_id.label("project_id"), func.count().label("hosts_count"))
            .group_by(Host.project_id)
            .subquery()
        )
        vulns_sq = (
            select(
                Vulnerability.project_id.label("project_id"),
                func.count().label("total_findings"),
                func.count()
                .filter(Vulnerability.status.in_((VulnerabilityStatus.OPEN, VulnerabilityStatus.IN_PROGRESS)))
                .label("open_findings"),
            )
            .group_by(Vulnerability.project_id)
            .subquery()
        )
        stmt = (
            select(
                Project.id,
                Project.status,
                func.coalesce(hosts_sq.c.hosts_count, 0),
                func.coalesce(vulns_sq.c.total_findings, 0),
                func.coalesce(vulns_sq.c.open_findings, 0),
            )
            .outerjoin(hosts_sq, hosts_sq.c.project_id == Project.id)
            .outerjoin(vulns_sq, vulns_sq.c.project_id == Project.id)
        )
        if current_user.role != UserRole.ADMIN:
            stmt = stmt.join(ProjectMember, ProjectMember.project_id == Project.id).where(
                ProjectMember.user_id == current_user.id
            )
        rows = (await self.db.execute(stmt)).all()
        return [
            {
                "project_id": project_id,
                "status": getattr(status, "value", status),
                "hosts_count": hosts_count,
                "total_findings": total_findings,
                "open_findings": open_findings,
            }
            for project_id, status, hosts_count, total_findings, open_findings in rows
        ]

    async def list_members(self, project_id: int) -> list[dict]:
        """Возвращает список участников проекта."""
        rows = (
            await self.db.execute(
                select(ProjectMember, User)
                .join(User, User.id == ProjectMember.user_id)
                .where(ProjectMember.project_id == project_id)
                .order_by(ProjectMember.added_at.desc())
            )
        ).all()
        return [
            {
                "user_id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "project_role": user.project_role,
                "added_at": member.added_at,
            }
            for member, user in rows
        ]

    async def _is_project_manager(self, project: Project, actor: User) -> bool:
        """Админ, создатель проекта или лид-участник.

        Роль лида глобальная (User.project_role), но возможности она открывает
        только внутри проектов, где пользователь действительно состоит.
        """
        if actor.role == UserRole.ADMIN or project.created_by == actor.id:
            return True
        if actor.project_role == ProjectRole.LEAD:
            membership = await self.db.scalar(
                select(ProjectMember).where(
                    and_(ProjectMember.project_id == project.id, ProjectMember.user_id == actor.id)
                )
            )
            return membership is not None
        return False

    async def ensure_can_manage_members(self, project_id: int, actor: User) -> Project:
        """Составом команды управляют: админ, создатель проекта или лид-участник."""
        project = await self.get_project(project_id)
        if await self._is_project_manager(project, actor):
            return project
        raise ForbiddenError("Управлять участниками может админ, лид проекта или его создатель")

    async def ensure_can_edit_project(self, project_id: int, actor: User) -> Project:
        """Карточку проекта (название/описание/сроки) правят те же роли, что и состав команды.

        Удаление проекта при этом остаётся строго за админом.
        """
        project = await self.get_project(project_id)
        if await self._is_project_manager(project, actor):
            return project
        raise ForbiddenError("Изменять проект может админ, лид проекта или его создатель")

    async def add_member(self, project_id: int, user_id: int, actor_id: int, ip_address: str | None = None) -> dict:
        """Добавляет пользователя в участники проекта."""
        await self.get_project(project_id)
        user = await self.db.scalar(select(User).where(User.id == user_id))
        if not user:
            raise NotFoundError("User not found")
        exists = await self.db.scalar(
            select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
        )
        if exists:
            raise ConflictError("Пользователь уже участник проекта")
        member = ProjectMember(project_id=project_id, user_id=user_id)
        self.db.add(member)
        # Повод №2: человека добавили в проект — он об этом узнаёт.
        # Себя добавивший не уведомляем.
        if user_id != actor_id:
            self.db.add(
                Notification(
                    user_id=user_id,
                    type=NotificationType.PROJECT_MEMBER_ADDED,
                    project_id=project_id,
                    actor_id=actor_id,
                    is_read=False,
                )
            )
        await self.db.commit()
        await self.db.refresh(member)
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="project_member",
            entity_id=member.id,
            details={"project_id": str(project_id), "username": user.username},
            ip_address=ip_address,
        )
        if user_id != actor_id:
            await ws_manager.notify_user(
                user_id,
                {
                    "event": "notification",
                    "entity": "notification",
                    "data": {"type": NotificationType.PROJECT_MEMBER_ADDED.value, "is_read": False, "project_id": str(project_id)},
                },
            )
        return {
            "user_id": user.id,
            "username": user.username,
            "project_role": user.project_role,
            "added_at": member.added_at,
        }

    async def remove_member(self, project_id: int, user_id: int, actor_id: int, ip_address: str | None = None) -> None:
        """Удаляет пользователя из участников проекта."""
        member = await self.db.scalar(
            select(ProjectMember).where(and_(ProjectMember.project_id == project_id, ProjectMember.user_id == user_id))
        )
        if not member:
            raise NotFoundError("Участник не найден")
        # Имя забираем до удаления: entity_id у записи — это id строки
        # project_members, по нему потом никого не найти, а сама связь исчезнет.
        # Без username в активности осталось бы «удалил участника #17».
        username = await self.db.scalar(select(User.username).where(User.id == user_id))
        await self.db.delete(member)
        await self.db.commit()
        await self.audit.log(
            "DELETE",
            user_id=actor_id,
            entity_type="project_member",
            entity_id=member.id,
            details={"project_id": str(project_id), "user_id": str(user_id), "username": username},
            ip_address=ip_address,
        )

    async def list_project_activity(self, project_id: int, limit: int = 50) -> list[dict]:
        """Активность проекта: события по всем его сущностям.

        Доступна любому участнику проекта (в отличие от глобального журнала
        `/audit-logs`, который остаётся админским). Скоуп собирается по
        entity_id каждой сущности проекта + fallback на details.project_id.
        """
        await self.get_project(project_id)

        host_ids = select(Host.id).where(Host.project_id == project_id)
        scope = or_(
            and_(AuditLog.entity_type == "project", AuditLog.entity_id == project_id),
            and_(AuditLog.entity_type == "vulnerability", AuditLog.entity_id.in_(select(Vulnerability.id).where(Vulnerability.project_id == project_id))),
            and_(AuditLog.entity_type == "host", AuditLog.entity_id.in_(host_ids)),
            and_(AuditLog.entity_type == "port", AuditLog.entity_id.in_(select(Port.id).where(Port.host_id.in_(host_ids)))),
            and_(
                AuditLog.entity_type == "service",
                AuditLog.entity_id.in_(select(Service.id).where(Service.port_id.in_(select(Port.id).where(Port.host_id.in_(host_ids))))),
            ),
            and_(AuditLog.entity_type == "endpoint", AuditLog.entity_id.in_(select(Endpoint.id).where(Endpoint.host_id.in_(host_ids)))),
            and_(AuditLog.entity_type == "project_note", AuditLog.entity_id.in_(select(ProjectNote.id).where(ProjectNote.project_id == project_id))),
            and_(AuditLog.entity_type == "project_member", AuditLog.entity_id.in_(select(ProjectMember.id).where(ProjectMember.project_id == project_id))),
            AuditLog.details["project_id"].as_string() == str(project_id),
        )
        stmt = (
            select(AuditLog, User.username)
            .outerjoin(User, User.id == AuditLog.user_id)
            .where(AuditLog.entity_type.is_not(None))
            .where(scope)
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()

        # Уязвимости обогащаем названием/severity и ссылкой на карточку.
        vuln_ids = [entry.entity_id for entry, _ in rows if entry.entity_type == "vulnerability" and entry.entity_id]
        vulns_by_id: dict[int, Vulnerability] = {}
        if vuln_ids:
            vulns_by_id = {
                v.id: v for v in (await self.db.scalars(select(Vulnerability).where(Vulnerability.id.in_(vuln_ids)))).all()
            }

        out: list[dict] = []
        for entry, username in rows:
            item: dict = {
                "id": entry.id,
                "action": entry.action,
                "entity_type": entry.entity_type,
                "entity_id": entry.entity_id,
                "user_id": entry.user_id,
                "username": username,
                "title": None,
                "severity": None,
                "url": None,
                "details": entry.details,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            }
            vuln = vulns_by_id.get(entry.entity_id) if entry.entity_type == "vulnerability" else None
            if vuln is not None:
                item["title"] = vuln.title
                item["severity"] = getattr(vuln.severity, "value", vuln.severity)
                item["url"] = f"/projects/{project_id}/vulns/{vuln.id}"
            out.append(item)
        return out

    async def list_folders(self) -> list[ProjectFolder]:
        """Возвращает список папок проектов."""
        rows = await self.db.scalars(select(ProjectFolder).order_by(ProjectFolder.path.asc()))
        return list(rows.all())

    async def create_folder(self, name: str, parent_id: int | None, actor_id: int, ip_address: str | None = None) -> ProjectFolder:
        """Создаёт новую папку проекта (в т.ч. вложенную)."""
        segment = self._normalize_folder_segment(name)
        parent: ProjectFolder | None = None
        if parent_id:
            parent = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == parent_id))
            if not parent:
                raise NotFoundError("Родительская папка не найдена")
        path = f"{parent.path}/{segment}" if parent else segment
        duplicate = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.path == path))
        if duplicate:
            raise ConflictError("Папка с таким путём уже существует")
        folder = ProjectFolder(name=segment, path=path, parent_id=parent_id, created_by=actor_id)
        self.db.add(folder)
        await self.db.commit()
        await self.db.refresh(folder)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="project_folder", entity_id=folder.id, ip_address=ip_address)
        await ws_manager.broadcast_projects_index(
            {"event": "created", "entity": "project_folder", "data": {"id": str(folder.id), "path": folder.path}}
        )
        return folder

    async def move_folder(
        self, folder_id: int, new_parent_id: int | None, actor_id: int, ip_address: str | None = None
    ) -> ProjectFolder:
        """Перемещает папку и пересчитывает пути дочерних папок и проектов."""
        folder = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == folder_id))
        if not folder:
            raise NotFoundError("Папка не найдена")
        if new_parent_id == folder.id:
            raise ValidationError("Нельзя переместить папку в саму себя")

        new_parent: ProjectFolder | None = None
        if new_parent_id:
            new_parent = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == new_parent_id))
            if not new_parent:
                raise NotFoundError("Родительская папка не найдена")
            if new_parent.path == folder.path or new_parent.path.startswith(f"{folder.path}/"):
                raise ValidationError("Нельзя переместить папку в её дочернюю папку")

        duplicate = await self.db.scalar(
            select(ProjectFolder).where(
                and_(
                    ProjectFolder.id != folder.id,
                    ProjectFolder.parent_id == new_parent_id,
                    ProjectFolder.name == folder.name,
                )
            )
        )
        if duplicate:
            raise ConflictError("В целевой папке уже есть папка с таким именем")

        old_path = folder.path
        new_path = f"{new_parent.path}/{folder.name}" if new_parent else folder.name
        if new_path == old_path and folder.parent_id == new_parent_id:
            return folder

        subtree_folders = (
            await self.db.scalars(
                select(ProjectFolder).where(or_(ProjectFolder.path == old_path, ProjectFolder.path.like(f"{old_path}/%")))
            )
        ).all()
        subtree_projects = (
            await self.db.scalars(select(Project).where(or_(Project.folder == old_path, Project.folder.like(f"{old_path}/%"))))
        ).all()

        for subtree_folder in subtree_folders:
            suffix = subtree_folder.path[len(old_path) :]
            subtree_folder.path = f"{new_path}{suffix}"
            if subtree_folder.id == folder.id:
                subtree_folder.parent_id = new_parent_id

        for project in subtree_projects:
            suffix = project.folder[len(old_path) :]
            project.folder = f"{new_path}{suffix}"

        await self.db.commit()
        await self.db.refresh(folder)
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="project_folder",
            entity_id=folder.id,
            details={"from": old_path, "to": new_path},
            ip_address=ip_address,
        )
        await ws_manager.broadcast_projects_index(
            {
                "event": "updated",
                "entity": "project_folder",
                "data": {"id": str(folder.id), "from": old_path, "to": new_path},
            }
        )
        return folder

    async def delete_folder(self, folder_id: int, actor_id: int, ip_address: str | None = None) -> dict:
        """Каскадно удаляет папку, все её подпапки и все проекты внутри.

        Возвращает счётчики удалённых сущностей для аудита.
        """
        folder = await self.db.scalar(select(ProjectFolder).where(ProjectFolder.id == folder_id))
        if not folder:
            raise NotFoundError("Папка не найдена")
        path = folder.path
        subtree_project_ids = list(
            (
                await self.db.scalars(
                    select(Project.id).where(or_(Project.folder == path, Project.folder.like(f"{path}/%")))
                )
            ).all()
        )
        subtree_folder_ids = list(
            (
                await self.db.scalars(
                    select(ProjectFolder.id).where(
                        or_(ProjectFolder.path == path, ProjectFolder.path.like(f"{path}/%"))
                    )
                )
            ).all()
        )
        if subtree_project_ids:
            await self.db.execute(delete(Project).where(Project.id.in_(subtree_project_ids)))
        if subtree_folder_ids:
            await self.db.execute(delete(ProjectFolder).where(ProjectFolder.id.in_(subtree_folder_ids)))
        await self.db.commit()
        summary = {
            "path": path,
            "deleted_folders": len(subtree_folder_ids),
            "deleted_projects": len(subtree_project_ids),
        }
        await self.audit.log(
            "DELETE",
            user_id=actor_id,
            entity_type="project_folder",
            entity_id=folder_id,
            details=summary,
            ip_address=ip_address,
        )
        await ws_manager.broadcast_projects_index(
            {
                "event": "deleted",
                "entity": "project_folder",
                "data": {"id": str(folder_id), "path": path, **summary},
            }
        )
        return summary


class AssetService:
    """Сервис CRUD для host/port/service/endpoint."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    @staticmethod
    def _normalize_endpoint_query_params(raw_params: list[dict] | None) -> list[dict]:
        normalized: list[dict] = []
        for item in raw_params or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            value = item.get("value")
            description = item.get("description")
            normalized.append(
                {
                    "name": name,
                    "value": None if value is None else str(value),
                    "required": bool(item.get("required", False)),
                    "description": None if description in (None, "") else str(description).strip(),
                }
            )
        return normalized

    _HTTP_HEADER_DROP = frozenset(
        {
            "referer",
            "referrer",
            "connection",
            "accept-encoding",
            "accept-language",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "user-agent",
            "host",
        }
    )

    _METHODS_WITHOUT_BODY = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})
    _UUID_PATH_SEGMENT_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )

    @staticmethod
    def _normalize_endpoint_path(path_value: str | None) -> str | None:
        if path_value is None:
            return None
        path_only, _ = AssetService._parse_request_target_token(str(path_value))
        normalized = re.sub(r"/{2,}", "/", (path_only or "/").strip() or "/")
        normalized = normalized if normalized.startswith("/") else f"/{normalized}"
        if normalized != "/" and normalized.endswith("/"):
            normalized = normalized[:-1]
        segments = [
            "{UUID}" if AssetService._UUID_PATH_SEGMENT_RE.fullmatch(segment) else segment
            for segment in normalized.split("/")
            if segment
        ]
        return f"/{'/'.join(segments)}" if segments else "/"

    @staticmethod
    def _normalize_endpoint_headers(raw_headers: list[dict] | None) -> list[dict]:
        normalized: list[dict] = []
        for item in raw_headers or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            value = item.get("value")
            normalized.append({"name": name, "value": "" if value is None else str(value)})
        return normalized

    @staticmethod
    def _sanitize_parsed_header_pairs(pairs: list[tuple[str, str]]) -> list[dict]:
        """Strip noisy/sensitive headers; Cookie/Authorization placeholders."""
        out: list[dict] = []
        had_cookie = False
        for name, value in pairs:
            ln = name.strip().lower()
            if ln in AssetService._HTTP_HEADER_DROP:
                continue
            if ln == "cookie":
                had_cookie = True
                continue
            if ln == "authorization":
                out.append({"name": "Authorization", "value": "{YOUR_CREDENTIALS_HERE}"})
                continue
            if ln == "content-type":
                continue
            out.append({"name": name.strip(), "value": value.strip()})
        if had_cookie:
            out.append({"name": "Cookie", "value": "{YOUR_TOKENS_HERE}"})
        return out

    @staticmethod
    def _sanitize_stored_header_items(raw: list[dict] | None) -> list[dict]:
        pairs: list[tuple[str, str]] = []
        for item in raw or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            value = str(item.get("value") or "")
            pairs.append((name, value))
        return AssetService._sanitize_parsed_header_pairs(pairs)

    @staticmethod
    def _parse_request_target_token(path_token: str) -> tuple[str, list[tuple[str, str]]]:
        token = path_token.strip()
        if token.startswith("http://") or token.startswith("https://"):
            u = urlparse(token)
            return u.path or "/", list(parse_qsl(u.query, keep_blank_values=True))
        fake = "http://stub.local" + (token if token.startswith("/") else "/" + token)
        u = urlparse(fake)
        return u.path or "/", list(parse_qsl(u.query, keep_blank_values=True))

    @staticmethod
    def _apply_structured_request_payload(payload: dict) -> dict:
        if "path" in payload and payload.get("path") is not None:
            payload["path"] = AssetService._normalize_endpoint_path(payload.get("path"))
        if "query_params" in payload:
            payload["query_params"] = AssetService._normalize_endpoint_query_params(payload.get("query_params"))
        if "request_headers" in payload and payload.get("request_headers") is not None:
            normalized = AssetService._normalize_endpoint_headers(payload.get("request_headers"))
            payload["request_headers"] = AssetService._sanitize_stored_header_items(normalized)
        if "request_body" in payload and payload.get("request_body") is not None:
            request_body = str(payload.get("request_body", ""))
            payload["request_body"] = request_body if request_body.strip() else None
        if "request_content_type" in payload and payload.get("request_content_type") is not None:
            content_type = str(payload.get("request_content_type", "")).strip()
            payload["request_content_type"] = content_type or None
        return payload

    @staticmethod
    def _apply_raw_request_payload(payload: dict) -> dict:
        request_raw = payload.get("request_raw")
        if not request_raw:
            payload.pop("request_raw", None)
            return payload
        raw_request = str(request_raw).replace("\r", "")
        parts = re.split(r"\n\s*\n", raw_request, maxsplit=1)
        header_block = parts[0]
        body = parts[1] if len(parts) > 1 else ""
        header_lines = header_block.split("\n")
        if not header_lines or not header_lines[0].strip():
            raise ValidationError("request_raw пустой")
        request_line = header_lines[0].split()
        if len(request_line) < 3:
            raise ValidationError("request_raw должен содержать request line вида 'METHOD /path HTTP/1.1'")
        method, path_value, http_part = request_line[0].upper(), request_line[1], request_line[2].upper()
        allowed_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if method not in allowed_methods:
            raise ValidationError("request_raw содержит неподдерживаемый HTTP-метод")
        if not http_part.startswith("HTTP/"):
            raise ValidationError("request_raw должен содержать HTTP-версию в request line")
        path_only, query_pairs = AssetService._parse_request_target_token(path_value)
        payload["method"] = method
        payload["path"] = AssetService._normalize_endpoint_path(path_only)
        if "query_params" not in payload or not payload.get("query_params"):
            payload["query_params"] = [
                {"name": key, "value": value, "required": False, "description": None} for key, value in query_pairs
            ]
        header_pairs: list[tuple[str, str]] = []
        for line in header_lines[1:]:
            line = line.strip()
            if not line or ":" not in line:
                continue
            h_name, _, h_val = line.partition(":")
            header_pairs.append((h_name.strip(), h_val))
        content_type = None
        for name, value in header_pairs:
            if name.lower() == "content-type":
                content_type = value.strip() or None
                break
        if ("request_body" not in payload or payload.get("request_body") is None) and body.strip():
            payload["request_body"] = body
        if ("request_content_type" not in payload or payload.get("request_content_type") is None) and content_type:
            payload["request_content_type"] = content_type
        if "request_headers" not in payload or not payload.get("request_headers"):
            payload["request_headers"] = AssetService._sanitize_parsed_header_pairs(header_pairs)
        if method in AssetService._METHODS_WITHOUT_BODY:
            payload["request_body"] = None
            payload["request_content_type"] = None
        payload.pop("request_raw", None)
        return payload

    @staticmethod
    def _merge_endpoint_fields(endpoint: Endpoint, endpoint_payload: dict) -> None:
        if not endpoint.description and endpoint_payload.get("description"):
            endpoint.description = endpoint_payload["description"]
        if not endpoint.query_params and endpoint_payload.get("query_params"):
            endpoint.query_params = endpoint_payload["query_params"]
        if not endpoint.request_body and endpoint_payload.get("request_body"):
            endpoint.request_body = endpoint_payload["request_body"]
        if not endpoint.request_content_type and endpoint_payload.get("request_content_type"):
            endpoint.request_content_type = endpoint_payload["request_content_type"]
        if not endpoint.request_headers and endpoint_payload.get("request_headers"):
            endpoint.request_headers = endpoint_payload["request_headers"]

    async def _get_host(self, project_id: int, host_id: int) -> Host:
        host = await self.db.scalar(
            select(Host)
            .options(selectinload(Host.ip_addresses).selectinload(HostIpAddress.ports).selectinload(Port.services))
            .where(and_(Host.id == host_id, Host.project_id == project_id))
        )
        if not host:
            raise NotFoundError("Хост не найден")
        return host

    @staticmethod
    def _normalize_host_ip_entries(
        primary_ip: str | None,
        raw_entries: list[str | dict] | None,
    ) -> list[dict]:
        entries: list[dict] = []
        seen: set[str] = set()

        def add_entry(ip_address: str | None, label: str | None = None, is_primary: bool = False) -> None:
            value = (ip_address or "").strip()
            if not value or value in seen:
                return
            seen.add(value)
            entries.append({"ip_address": value, "label": label, "is_primary": is_primary})

        for raw in raw_entries or []:
            if isinstance(raw, str):
                add_entry(raw)
            else:
                add_entry(raw.get("ip_address"), raw.get("label"), bool(raw.get("is_primary")))

        if primary_ip:
            primary = primary_ip.strip()
            matched = False
            for entry in entries:
                if entry["ip_address"] == primary:
                    entry["is_primary"] = True
                    matched = True
                else:
                    entry["is_primary"] = False
            if not matched:
                entries.insert(0, {"ip_address": primary, "label": None, "is_primary": True})

        primary_seen = False
        for entry in entries:
            if entry["is_primary"] and not primary_seen:
                primary_seen = True
            else:
                entry["is_primary"] = False
        if entries and not primary_seen:
            entries[0]["is_primary"] = True
        return entries

    async def _replace_host_ip_addresses(self, host: Host, entries: list[dict]) -> None:
        # Инкрементально обновляем список IP, чтобы не каскадно сносить порты при
        # сохранении хоста: совпадающие по ip_address записи переиспользуем,
        # отсутствующие — удаляем (порты на них уйдут каскадом).
        existing: dict[str, HostIpAddress] = {
            row.ip_address: row for row in list(host.ip_addresses)
        }
        desired_values: set[str] = {entry["ip_address"] for entry in entries}

        for old_ip, row in list(existing.items()):
            if old_ip not in desired_values:
                await self.db.delete(row)

        result_rows: list[HostIpAddress] = []
        for entry in entries:
            value = entry["ip_address"]
            row = existing.get(value)
            if row is None:
                row = HostIpAddress(
                    host_id=host.id,
                    ip_address=value,
                    label=entry.get("label"),
                    is_primary=bool(entry.get("is_primary")),
                    # Ручное добавление не пробивает — CF знаем только по CIDR:
                    # True если в диапазонах CF, иначе None (неизвестно), не False.
                    is_cloudflare=is_cloudflare_ip(value) or None,
                )
                self.db.add(row)
            else:
                row.label = entry.get("label")
                row.is_primary = bool(entry.get("is_primary"))
                # Переиспользуемая строка сохраняет hostnames. CF по CIDR: True если
                # в диапазонах; иначе НЕ понижаем (пробив мог достоверно определить CF/не-CF).
                if is_cloudflare_ip(value):
                    row.is_cloudflare = True
            result_rows.append(row)

        host.ip_address = next(
            (row.ip_address for row in result_rows if row.is_primary),
            result_rows[0].ip_address if result_rows else None,
        )
        set_committed_value(host, "ip_addresses", result_rows)

    async def _get_port(self, host_id: int, port_id: int) -> Port:
        port = await self.db.scalar(select(Port).where(and_(Port.id == port_id, Port.host_id == host_id)))
        if not port:
            raise NotFoundError("Порт не найден")
        return port

    async def list_hosts(
        self, project_id: int, page: int, size: int, status: str | None, origin: str = "host"
    ) -> tuple[list[Host], int]:
        """origin: host — обычные хосты (по умолчанию), ip — служебные родители
        адресов из фермы IP, all — и те и другие (нужно фронту: один запрос
        кормит и таблицу хостов, и таблицу IP)."""
        base_query = select(Host).where(Host.project_id == project_id)
        if origin != "all":
            base_query = base_query.where(Host.origin == origin)
        if status:
            base_query = base_query.where(Host.status == status)
        total = await self.db.scalar(select(func.count()).select_from(base_query.subquery())) or 0
        items_query = (
            base_query.options(selectinload(Host.ip_addresses).selectinload(HostIpAddress.ports).selectinload(Port.services))
            .order_by(Host.created_at.desc())
            .offset((page - 1) * size)
            .limit(size)
        )
        items = (await self.db.scalars(items_query)).all()
        return list(items), total

    async def create_host(self, project_id: int, payload: dict, actor_id: int) -> Host:
        ip_entries = self._normalize_host_ip_entries(payload.pop("ip_address", None), payload.pop("ip_addresses", None))
        host = Host(project_id=project_id, ip_address=ip_entries[0]["ip_address"] if ip_entries else None, **payload)
        self.db.add(host)
        await self.db.flush()
        # Хост только что создан — коллекция IP пуста; проставляем её явно, чтобы
        # _replace_host_ip_addresses не пытался лениво подгрузить связь вне greenlet
        # (async SQLAlchemy: ленивый lazy-load здесь падает с MissingGreenlet).
        set_committed_value(host, "ip_addresses", [])
        await self._replace_host_ip_addresses(host, ip_entries)
        await self.db.commit()
        await self.audit.log("CREATE", user_id=actor_id, entity_type="host", entity_id=host.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})
        return await self._get_host(project_id, host.id)

    async def get_host(self, project_id: int, host_id: int) -> dict:
        host = await self._get_host(project_id, host_id)
        endpoints = (await self.db.scalars(select(Endpoint).where(Endpoint.host_id == host.id))).all()
        return {
            "id": host.id,
            "project_id": host.project_id,
            "ip_address": host.ip_address,
            "ip_addresses": [
                {
                    "id": ip.id,
                    "host_id": ip.host_id,
                    "ip_address": ip.ip_address,
                    "label": ip.label,
                    "is_primary": ip.is_primary,
                    "hostnames": ip.hostnames or [],
                    "is_cloudflare": ip.is_cloudflare,
                    "ports": [
                        {
                            "id": port.id,
                            "host_id": port.host_id,
                            "ip_address_id": port.ip_address_id,
                            "port_number": port.port_number,
                            "protocol": port.protocol,
                            "state": port.state,
                            "http_status": port.http_status,
                            "services": [
                                {
                                    "id": svc.id,
                                    "port_id": svc.port_id,
                                    "name": svc.name,
                                    "version": svc.version,
                                    "banner": svc.banner,
                                    "created_at": svc.created_at,
                                    "updated_at": svc.updated_at,
                                }
                                for svc in port.services
                            ],
                            "created_at": port.created_at,
                            "updated_at": port.updated_at,
                        }
                        for port in sorted(ip.ports, key=lambda p: p.port_number)
                    ],
                    "created_at": ip.created_at,
                    "updated_at": ip.updated_at,
                }
                for ip in host.ip_addresses
            ],
            "hostname": host.hostname,
            "status": host.status,
            "os_type": host.os_type,
            "notes": host.notes,
            "origin": host.origin,
            "created_at": host.created_at,
            "updated_at": host.updated_at,
            "endpoints": [
                {
                    "id": endpoint.id,
                    "host_id": endpoint.host_id,
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "description": endpoint.description,
                    "query_params": endpoint.query_params or [],
                    "request_body": endpoint.request_body,
                    "request_content_type": endpoint.request_content_type,
                    "request_headers": endpoint.request_headers or [],
                    "created_at": endpoint.created_at,
                    "updated_at": endpoint.updated_at,
                }
                for endpoint in endpoints
            ],
        }

    async def update_host(self, project_id: int, host_id: int, payload: dict, actor_id: int) -> Host:
        host = await self._get_host(project_id, host_id)
        has_ip_payload = "ip_addresses" in payload or "ip_address" in payload
        raw_ip_entries = payload.pop("ip_addresses", None)
        primary_ip = payload.pop("ip_address", None)
        for key, value in payload.items():
            if value is not None:
                setattr(host, key, value)
        if has_ip_payload:
            ip_entries = self._normalize_host_ip_entries(primary_ip, raw_ip_entries)
            if not ip_entries and not host.hostname:
                raise ValidationError("Нужно указать хотя бы один IP-адрес или hostname")
            await self._replace_host_ip_addresses(host, ip_entries)
        await self.db.commit()
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="host", entity_id=host.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})
        return await self._get_host(project_id, host.id)

    async def delete_host(self, project_id: int, host_id: int, actor_id: int) -> None:
        host = await self._get_host(project_id, host_id)
        # Имя фиксируем до удаления: после него в активности остался бы «#12».
        details = {"project_id": str(project_id), "hostname": host.hostname, "ip_address": host.ip_address}
        await self.db.delete(host)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="host", entity_id=host.id, details=details)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "host", "project_id": str(project_id), "data": {"id": str(host.id)}})

    # ------------------------------------------------------------------
    # Скрытие IP из списка IP (мягкое «удаление» адреса из вкладки IP).
    # Привязку адреса к домен-хостам (origin='host') НЕ трогаем — она остаётся
    # в карточке хоста; удаляем лишь отдельную IP-запись (Host origin='ip') и
    # заносим адрес в project_hidden_ips, чтобы вкладка IP его не показывала.
    # ------------------------------------------------------------------
    async def list_hidden_ips(self, project_id: int) -> list[str]:
        rows = await self.db.scalars(
            select(ProjectHiddenIp.ip_address).where(ProjectHiddenIp.project_id == project_id)
        )
        return list(rows.all())

    async def hide_ip(self, project_id: int, ip_address: str, actor_id: int) -> None:
        """«Удаляет» адрес из списка IP: сносит отдельные IP-хосты (origin='ip') с
        этим адресом и запоминает адрес как скрытый. Домен-хосты не трогаются."""
        ip = (ip_address or "").strip()
        if not ip:
            raise ValidationError("Не указан IP-адрес")
        # Отдельные IP-записи (ферма IP) с этим адресом — удаляем целиком, каскад
        # уносит их HostIpAddress и порты. Домен-хостов (origin='host') не касаемся.
        standalone = await self.db.scalars(
            select(Host)
            .join(HostIpAddress, HostIpAddress.host_id == Host.id)
            .where(and_(Host.project_id == project_id, Host.origin == "ip", HostIpAddress.ip_address == ip))
        )
        for host in list(dict.fromkeys(standalone.all())):
            await self.db.delete(host)
        # Идемпотентно заносим адрес в скрытые (уникальный ключ project_id+ip).
        existing = await self.db.scalar(
            select(ProjectHiddenIp).where(
                and_(ProjectHiddenIp.project_id == project_id, ProjectHiddenIp.ip_address == ip)
            )
        )
        if existing is None:
            self.db.add(ProjectHiddenIp(project_id=project_id, ip_address=ip, created_by=actor_id))
        await self.db.commit()
        await self.audit.log(
            "DELETE", user_id=actor_id, entity_type="ip_address", entity_id=None, details={"project_id": str(project_id), "ip_address": ip}
        )
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "host", "project_id": str(project_id), "data": {"ip_address": ip}})

    async def unhide_ip(self, project_id: int, ip_address: str, actor_id: int) -> None:
        """Снимает адрес со скрытия — он снова показывается в списке IP (если хоть
        один хост его несёт). Тем же пользуется явное «Add IPs» (см. фермy IP)."""
        ip = (ip_address or "").strip()
        await self.db.execute(
            delete(ProjectHiddenIp).where(
                and_(ProjectHiddenIp.project_id == project_id, ProjectHiddenIp.ip_address == ip)
            )
        )
        await self.db.commit()
        await self.audit.log(
            "UPDATE", user_id=actor_id, entity_type="ip_address", entity_id=None, details={"project_id": str(project_id), "ip_address": ip, "unhidden": True}
        )
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "host", "project_id": str(project_id), "data": {"ip_address": ip}})

    async def list_ports(self, host_id: int, ip_address_id: int | None = None) -> list[Port]:
        query = select(Port).where(Port.host_id == host_id).order_by(Port.port_number)
        if ip_address_id is not None:
            query = query.where(Port.ip_address_id == ip_address_id)
        return list((await self.db.scalars(query)).all())

    async def _get_host_ip(self, host_id: int, ip_address_id: int) -> HostIpAddress:
        ip = await self.db.scalar(
            select(HostIpAddress).where(
                and_(HostIpAddress.id == ip_address_id, HostIpAddress.host_id == host_id)
            )
        )
        if not ip:
            raise ValidationError("IP-адрес не принадлежит указанному хосту")
        return ip

    async def create_port(self, project_id: int, host_id: int, payload: dict, actor_id: int) -> Port:
        await self._get_host(project_id, host_id)
        ip_address_id = payload["ip_address_id"]
        await self._get_host_ip(host_id, ip_address_id)
        duplicate = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.ip_address_id == ip_address_id,
                    Port.port_number == payload["port_number"],
                    Port.protocol == payload["protocol"],
                )
            )
        )
        if duplicate:
            raise ConflictError("Порт с таким номером и протоколом уже существует на этом IP")
        port = Port(host_id=host_id, **payload)
        self.db.add(port)
        await self.db.commit()
        await self.db.refresh(port)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})
        return port

    async def get_port(self, host_id: int, port_id: int) -> Port:
        return await self._get_port(host_id, port_id)

    async def update_port(self, project_id: int, host_id: int, port_id: int, payload: dict, actor_id: int) -> Port:
        port = await self._get_port(host_id, port_id)
        next_port_number = payload.get("port_number", port.port_number)
        next_protocol = payload.get("protocol", port.protocol)
        next_ip_address_id = payload.get("ip_address_id", port.ip_address_id)
        if next_ip_address_id != port.ip_address_id:
            await self._get_host_ip(host_id, next_ip_address_id)
        duplicate = await self.db.scalar(
            select(Port).where(
                and_(
                    Port.ip_address_id == next_ip_address_id,
                    Port.id != port.id,
                    Port.port_number == next_port_number,
                    Port.protocol == next_protocol,
                )
            )
        )
        if duplicate:
            raise ConflictError("Порт с таким номером и протоколом уже существует на этом IP")
        for key, value in payload.items():
            if value is not None:
                setattr(port, key, value)
        await self.db.commit()
        await self.db.refresh(port)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})
        return port

    async def delete_port(self, project_id: int, host_id: int, port_id: int, actor_id: int) -> None:
        port = await self._get_port(host_id, port_id)
        await self.db.delete(port)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="port", entity_id=port.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "port", "project_id": str(project_id), "data": {"id": str(port.id)}})

    async def list_services(self, port_id: int) -> list[Service]:
        return list((await self.db.scalars(select(Service).where(Service.port_id == port_id).order_by(Service.created_at.desc()))).all())

    async def create_service(self, project_id: int, host_id: int, port_id: int, payload: dict, actor_id: int) -> Service:
        await self._get_host(project_id, host_id)
        await self._get_port(host_id, port_id)
        service = Service(port_id=port_id, **payload)
        self.db.add(service)
        await self.db.commit()
        await self.db.refresh(service)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})
        return service

    async def update_service(
        self, project_id: int, host_id: int, port_id: int, service_id: int, payload: dict, actor_id: int
    ) -> Service:
        await self._get_host(project_id, host_id)
        await self._get_port(host_id, port_id)
        service = await self.db.scalar(select(Service).where(and_(Service.id == service_id, Service.port_id == port_id)))
        if not service:
            raise NotFoundError("Сервис не найден")
        for key, value in payload.items():
            if value is not None:
                setattr(service, key, value)
        await self.db.commit()
        await self.db.refresh(service)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})
        return service

    async def delete_service(self, project_id: int, port_id: int, service_id: int, actor_id: int) -> None:
        service = await self.db.scalar(select(Service).where(and_(Service.id == service_id, Service.port_id == port_id)))
        if not service:
            raise NotFoundError("Сервис не найден")
        await self.db.delete(service)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="service", entity_id=service.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "service", "project_id": str(project_id), "data": {"id": str(service.id)}})

    async def list_endpoints(self, host_id: int) -> list[Endpoint]:
        return list((await self.db.scalars(select(Endpoint).where(Endpoint.host_id == host_id).order_by(Endpoint.created_at.desc()))).all())

    async def list_js_files(self, project_id: int) -> list[dict]:
        """JS-файлы проекта с секретами и именем хоста — для раздела JS.

        Отдаём готовые dict (а не ORM), чтобы подставить hostname хоста рядом с
        host_id: JsFileOut его ждёт, а связи Host→JsFile нет.
        """
        files = (
            await self.db.scalars(
                select(JsFile)
                .options(selectinload(JsFile.secrets))
                .where(JsFile.project_id == project_id)
                .order_by(JsFile.secret_count.desc(), JsFile.url)
            )
        ).all()
        host_names = dict(
            (await self.db.execute(select(Host.id, Host.hostname).where(Host.project_id == project_id))).all()
        )
        return [
            {
                "id": f.id,
                "host_id": f.host_id,
                "hostname": host_names.get(f.host_id),
                "url": f.url,
                "status": f.status,
                "size_bytes": f.size_bytes,
                "content_type": f.content_type,
                "secret_count": f.secret_count,
                "endpoint_count": f.endpoint_count,
                "endpoints": f.endpoints or [],
                "secrets": [
                    {
                        "kind": s.kind,
                        "match_preview": s.match_preview,
                        "snippet": s.snippet,
                        "severity": s.severity,
                    }
                    for s in f.secrets
                ],
                "fetched_at": f.fetched_at,
            }
            for f in files
        ]

    async def create_endpoint(self, project_id: int, host_id: int, payload: dict, actor_id: int) -> Endpoint:
        await self._get_host(project_id, host_id)
        payload = self._apply_structured_request_payload(self._apply_raw_request_payload(dict(payload)))
        if payload.get("request_headers") is None:
            payload["request_headers"] = []
        duplicate = await self.db.scalar(
            select(Endpoint).where(
                and_(
                    Endpoint.host_id == host_id,
                    Endpoint.path == payload.get("path"),
                    Endpoint.method == payload.get("method"),
                )
            )
        )
        if duplicate:
            self._merge_endpoint_fields(duplicate, payload)
            await self.db.commit()
            await self.db.refresh(duplicate)
            await self.audit.log("UPDATE", user_id=actor_id, entity_type="endpoint", entity_id=duplicate.id)
            await ws_manager.broadcast(project_id, {"event": "updated", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(duplicate.id)}})
            return duplicate
        endpoint = Endpoint(host_id=host_id, **payload)
        self.db.add(endpoint)
        await self.db.commit()
        await self.db.refresh(endpoint)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})
        return endpoint

    async def update_endpoint(self, project_id: int, host_id: int, endpoint_id: int, payload: dict, actor_id: int) -> Endpoint:
        await self._get_host(project_id, host_id)
        payload = self._apply_structured_request_payload(self._apply_raw_request_payload(dict(payload)))
        endpoint = await self.db.scalar(select(Endpoint).where(and_(Endpoint.id == endpoint_id, Endpoint.host_id == host_id)))
        if not endpoint:
            raise NotFoundError("Endpoint не найден")
        next_path = payload.get("path") if payload.get("path") is not None else endpoint.path
        next_method = payload.get("method") if payload.get("method") is not None else endpoint.method
        duplicate = await self.db.scalar(
            select(Endpoint).where(
                and_(
                    Endpoint.host_id == host_id,
                    Endpoint.id != endpoint_id,
                    Endpoint.path == next_path,
                    Endpoint.method == next_method,
                )
            )
        )
        if duplicate:
            raise ConflictError("Эндпоинт с таким методом и path уже существует")
        for key, value in payload.items():
            if key in {"description", "request_body", "request_content_type", "query_params", "request_headers"} or value is not None:
                setattr(endpoint, key, value)
        await self.db.commit()
        await self.db.refresh(endpoint)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})
        return endpoint

    async def delete_endpoint(self, project_id: int, host_id: int, endpoint_id: int, actor_id: int) -> None:
        endpoint = await self.db.scalar(select(Endpoint).where(and_(Endpoint.id == endpoint_id, Endpoint.host_id == host_id)))
        if not endpoint:
            raise NotFoundError("Endpoint не найден")
        details = {"project_id": str(project_id), "endpoint": f"{endpoint.method.value if endpoint.method else ''} {endpoint.path}".strip()}
        await self.db.delete(endpoint)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="endpoint", entity_id=endpoint.id, details=details)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "endpoint", "project_id": str(project_id), "data": {"id": str(endpoint.id)}})


class VulnerabilityService:
    """Сервис управления уязвимостями и привязками активов."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _get_vuln(self, project_id: int, vuln_id: int) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        self._hydrate_workflow_steps(vuln)
        return vuln

    # «1. Шаг» / «2) Шаг» / «- Шаг» — нумерацию/маркер убираем: номер шага рисует UI.
    _STEP_MARKER_RE = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s*")

    @staticmethod
    def _split_steps_text(text: str) -> list[str]:
        """Разбивает текстовые шаги воспроизведения на отдельные шаги.

        Каждый пункт («1. …») — отдельный шаг: на фронте у него своя карточка.
        Если нумерации нет, абзацы/строки тоже считаем отдельными шагами, а весь
        текст одной строкой остаётся одним шагом.
        """
        lines = [line.strip() for line in text.replace("\r", "").split("\n")]
        steps: list[str] = []
        for line in lines:
            if not line:
                continue
            stripped = VulnerabilityService._STEP_MARKER_RE.sub("", line).strip()
            if not stripped:
                continue
            # Продолжение предыдущего шага: строка без маркера дописывается к нему.
            if steps and stripped == line:
                steps[-1] = f"{steps[-1]}\n{stripped}"
            else:
                steps.append(stripped)
        return steps

    @staticmethod
    def _hydrate_workflow_steps(vuln: Vulnerability) -> None:
        """Достраивает workflow_steps для находок, у которых есть только текст.

        Такое приходит из старых данных, импорта и агентов: раскладываем текст по
        отдельным шагам, иначе весь список схлопывается в одно поле в карточке.
        """
        if vuln.workflow_steps is not None:
            return
        hydrated_steps: list[dict] = [
            {"id": str(uuid4()), "description": description, "image_file_ids": []}
            for description in VulnerabilityService._split_steps_text(vuln.steps_to_reproduce or "")
        ]
        if hasattr(vuln, "_sa_instance_state"):
            set_committed_value(vuln, "workflow_steps", hydrated_steps)
        else:
            vuln.workflow_steps = hydrated_steps

    @staticmethod
    def _normalize_workflow_steps(steps: list[dict] | None) -> list[dict]:
        normalized: list[dict] = []
        raw_steps = steps or []
        for raw_step in raw_steps:
            description = str(raw_step.get("description", "")).strip()
            endpoint_request_raw = str(raw_step.get("endpoint_request_raw", "")).strip()
            endpoint_id = raw_step.get("endpoint_id")
            image_file_ids = [int(file_id) for file_id in raw_step.get("image_file_ids", []) if file_id]
            if not description and not image_file_ids and not endpoint_id and not endpoint_request_raw:
                continue
            normalized.append(
                {
                    "id": str(raw_step.get("id") or uuid4()),
                    "description": description or None,
                    "image_file_ids": image_file_ids,
                    "endpoint_id": int(endpoint_id) if endpoint_id else None,
                    "endpoint_request_raw": endpoint_request_raw or None,
                }
            )
        return normalized

    @staticmethod
    def _workflow_steps_to_text(steps: list[dict]) -> str | None:
        if not steps:
            return None
        blocks: list[str] = []
        for index, step in enumerate(steps, start=1):
            description = str(step.get("description", "")).strip()
            block = f"{index}. Этап {index}"
            if description:
                block = f"{block}\n{description}"
            if step.get("endpoint_id") or step.get("endpoint_request_raw"):
                block = f"{block}\n[Endpoint: привязан]"
            if step.get("image_file_ids"):
                block = f"{block}\n[Изображений: {len(step['image_file_ids'])}]"
            blocks.append(block)
        return "\n\n".join(blocks)

    @staticmethod
    def _normalize_cvss_vector(version: str | None, vector: str | None) -> str | None:
        version_value = getattr(version, "value", version)
        if not version or not vector:
            return None
        raw = vector.strip()
        if not raw:
            return None
        normalized = re.sub(r"^CVSS:\d\.\d/", f"CVSS:{version_value}/", raw)
        if not normalized.startswith("CVSS:"):
            normalized = f"CVSS:{version_value}/{normalized.lstrip('/')}"
        return normalized

    @staticmethod
    def _calculate_cvss_score(version: str | None, vector: str | None) -> tuple[str | None, float | None]:
        version_value = getattr(version, "value", version)
        normalized_vector = VulnerabilityService._normalize_cvss_vector(version, vector)
        if not normalized_vector:
            return None, None
        try:
            if version_value == "4.0":
                score = float(CVSS4(normalized_vector).scores()[0])
            else:
                raise ValidationError("Поддерживается только CVSS 4.0")
        except Exception as exc:
            raise ValidationError(f"Некорректный CVSS вектор: {exc}") from exc
        return normalized_vector, score

    @staticmethod
    def _apply_calculated_cvss_fields(payload: dict, *, current_version: str | None = None, current_vector: str | None = None) -> None:
        has_explicit_score = payload.get("cvss_score") is not None
        next_version = getattr(payload.get("cvss_version", current_version), "value", payload.get("cvss_version", current_version))
        next_vector = payload.get("cvss_vector", current_vector)

        if "cvss_vector" in payload and not payload.get("cvss_vector"):
            if has_explicit_score:
                raise ValidationError("CVSS score рассчитывается автоматически и требует корректный CVSS 4.0 вектор")
            payload["cvss_version"] = None
            payload["cvss_vector"] = None
            payload["cvss_score"] = None
            return

        if next_vector:
            if not next_version:
                raise ValidationError("Для расчёта CVSS укажите версию 4.0 и корректный вектор")
            normalized_vector, calculated_score = VulnerabilityService._calculate_cvss_score(next_version, next_vector)
            payload["cvss_version"] = next_version
            payload["cvss_vector"] = normalized_vector
            payload["cvss_score"] = calculated_score
            return

        if has_explicit_score:
            raise ValidationError("CVSS score рассчитывается автоматически и требует корректный CVSS 4.0 вектор")

        if "cvss_version" in payload and payload.get("cvss_version"):
            raise ValidationError("Для расчёта CVSS укажите корректный CVSS 4.0 вектор")

    @staticmethod
    def _severity_from_cvss_score(score: float | None) -> Severity:
        if score is None:
            return Severity.INFO
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        if score > 0:
            return Severity.LOW
        return Severity.INFO

    async def _resolve_workflow_step_endpoints(self, project_id: int, host_id: int, steps: list[dict]) -> list[dict]:
        resolved_steps: list[dict] = []
        for step in steps:
            next_step = dict(step)
            endpoint_id_raw = next_step.get("endpoint_id")
            endpoint_request_raw = next_step.get("endpoint_request_raw")
            endpoint_id = int(endpoint_id_raw) if endpoint_id_raw else None
            if endpoint_id:
                endpoint = await self.db.scalar(
                    select(Endpoint).where(and_(Endpoint.id == endpoint_id, Endpoint.host_id == host_id))
                )
                if endpoint:
                    next_step["endpoint_id"] = endpoint.id
                else:
                    # Endpoint указывать необязательно — невалидную привязку просто сбрасываем,
                    # вместо того чтобы возвращать 400.
                    next_step["endpoint_id"] = None
                    endpoint_id = None
            if endpoint_request_raw:
                try:
                    endpoint_payload = AssetService._apply_structured_request_payload(
                        AssetService._apply_raw_request_payload({"request_raw": endpoint_request_raw})
                    )
                except ValidationError:
                    # Невалидный raw-запрос не должен ронять сохранение этапа — endpoint опционален.
                    next_step["endpoint_request_raw"] = None
                    resolved_steps.append(next_step)
                    continue
                existing_endpoint = await self.db.scalar(
                    select(Endpoint).where(
                        and_(
                            Endpoint.host_id == host_id,
                            Endpoint.path == endpoint_payload["path"],
                            Endpoint.method == endpoint_payload.get("method"),
                        )
                    )
                )
                endpoint = existing_endpoint
                if endpoint is None:
                    if endpoint_payload.get("request_headers") is None:
                        endpoint_payload["request_headers"] = []
                    endpoint = Endpoint(host_id=host_id, **endpoint_payload)
                    self.db.add(endpoint)
                    await self.db.flush()
                next_step["endpoint_id"] = endpoint.id
                next_step["endpoint_request_raw"] = str(endpoint_request_raw).strip()
            resolved_steps.append(next_step)
        return resolved_steps

    async def _get_primary_host_id(self, vuln_id: int) -> int:
        host_id = await self.db.scalar(
            select(VulnerabilityAsset.asset_id)
            .where(and_(VulnerabilityAsset.vulnerability_id == vuln_id, VulnerabilityAsset.asset_type == AssetType.HOST))
            .limit(1)
        )
        if not host_id:
            raise ValidationError("Уязвимость должна быть привязана хотя бы к одному хосту")
        return host_id

    async def _validate_workflow_step_images(self, vulnerability_id: int | None, steps: list[dict] | None) -> None:
        image_ids = {
            int(file_id)
            for step in steps or []
            for file_id in step.get("image_file_ids", [])
            if file_id
        }
        if not image_ids:
            return
        if vulnerability_id is None:
            raise ValidationError("Нельзя указывать image_file_ids до загрузки файлов уязвимости")
        existing_ids = set(
            (
                await self.db.scalars(
                    select(File.id).where(and_(File.vulnerability_id == vulnerability_id, File.id.in_(list(image_ids))))
                )
            ).all()
        )
        missing_ids = sorted(str(file_id) for file_id in image_ids - existing_ids)
        if missing_ids:
            raise ValidationError(
                f"workflow_steps.image_file_ids содержат файлы, не принадлежащие уязвимости: {', '.join(missing_ids)}"
            )

    async def list(self, project_id: int, page: int, size: int, severity: str | None, status: str | None) -> tuple[list[Vulnerability], int]:
        query = select(Vulnerability).where(Vulnerability.project_id == project_id)
        if severity:
            query = query.where(Vulnerability.severity == severity)
        if status:
            query = query.where(Vulnerability.status == status)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = (await self.db.scalars(query.order_by(Vulnerability.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        for item in items:
            self._hydrate_workflow_steps(item)
        return list(items), total

    async def list_for_host(
        self, project_id: int, host_id: int, page: int, size: int, severity: str | None, status: str | None
    ) -> tuple[list[Vulnerability], int]:
        host_exists = await self.db.scalar(select(Host.id).where(and_(Host.id == host_id, Host.project_id == project_id)))
        if not host_exists:
            raise NotFoundError("Хост не найден")

        query = (
            select(Vulnerability)
            .join(VulnerabilityAsset, VulnerabilityAsset.vulnerability_id == Vulnerability.id)
            .where(
                and_(
                    Vulnerability.project_id == project_id,
                    VulnerabilityAsset.asset_type == AssetType.HOST,
                    VulnerabilityAsset.asset_id == host_id,
                )
            )
        )
        if severity:
            query = query.where(Vulnerability.severity == severity)
        if status:
            query = query.where(Vulnerability.status == status)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        items = (await self.db.scalars(query.order_by(Vulnerability.created_at.desc()).offset((page - 1) * size).limit(size))).all()
        for item in items:
            self._hydrate_workflow_steps(item)
        return list(items), total

    async def create(self, project_id: int, payload: dict, actor_id: int) -> Vulnerability:
        host_id = payload.pop("host_id", None)
        if not host_id:
            raise ValidationError("Уязвимость должна быть привязана к конкретному хосту")
        await self._assert_asset_in_project(project_id, AssetType.HOST, host_id)
        self._apply_calculated_cvss_fields(payload)
        if payload.get("cvss_score") is not None:
            payload["severity"] = self._severity_from_cvss_score(payload.get("cvss_score"))
        if "workflow_steps" in payload:
            payload["workflow_steps"] = self._normalize_workflow_steps(payload.get("workflow_steps"))
            payload["workflow_steps"] = await self._resolve_workflow_step_endpoints(project_id, host_id, payload["workflow_steps"])
            await self._validate_workflow_step_images(None, payload["workflow_steps"])
            payload["steps_to_reproduce"] = self._workflow_steps_to_text(payload["workflow_steps"])
        vuln = Vulnerability(project_id=project_id, created_by=actor_id, **payload)
        self.db.add(vuln)
        await self.db.flush()
        self.db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.HOST, asset_id=host_id))
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="vulnerability",
            entity_id=vuln.id,
            details={"host_id": str(host_id)},
        )
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        return vuln

    async def get(self, project_id: int, vuln_id: int) -> dict:
        vuln = await self._get_vuln(project_id, vuln_id)
        links = (await self.db.scalars(select(VulnerabilityAsset).where(VulnerabilityAsset.vulnerability_id == vuln.id))).all()
        files = (await self.db.scalars(select(File).where(File.vulnerability_id == vuln.id))).all()
        comments_count = await self.db.scalar(select(func.count()).select_from(Comment).where(Comment.vulnerability_id == vuln.id)) or 0
        return {"vulnerability": vuln, "assets": list(links), "files": list(files), "comments_count": comments_count}

    async def update(self, project_id: int, vuln_id: int, payload: dict, actor_id: int) -> Vulnerability:
        vuln = await self._get_vuln(project_id, vuln_id)
        # Статус меняют и здесь (карточка находки шлёт его в общем PUT), а не
        # только через patch_status — уведомление автору нужно в обоих путях.
        old_status = vuln.status
        self._apply_calculated_cvss_fields(
            payload,
            current_version=vuln.cvss_version.value if vuln.cvss_version else None,
            current_vector=vuln.cvss_vector,
        )
        next_score = payload.get("cvss_score", vuln.cvss_score)
        if next_score is not None:
            payload["severity"] = self._severity_from_cvss_score(next_score)
        if "workflow_steps" in payload:
            payload["workflow_steps"] = self._normalize_workflow_steps(payload.get("workflow_steps"))
            host_id = await self._get_primary_host_id(vuln.id)
            payload["workflow_steps"] = await self._resolve_workflow_step_endpoints(project_id, host_id, payload["workflow_steps"])
            await self._validate_workflow_step_images(vuln.id, payload["workflow_steps"])
            payload["steps_to_reproduce"] = self._workflow_steps_to_text(payload["workflow_steps"])
        clearable_fields = {"description", "cvss_version", "cvss_score", "cvss_vector", "cwe_id", "impact", "recommendations"}
        for key, value in payload.items():
            if key == "steps_to_reproduce" and "workflow_steps" in payload:
                setattr(vuln, key, value)
            elif key in clearable_fields or value is not None:
                setattr(vuln, key, value)
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="vulnerability", entity_id=vuln.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        if old_status != vuln.status:
            await self._notify_vuln_status_changed(vuln, actor_id)
        return vuln

    async def patch_status(self, project_id: int, vuln_id: int, status: str, actor_id: int) -> Vulnerability:
        vuln = await self._get_vuln(project_id, vuln_id)
        old_status = vuln.status
        vuln.status = status
        await self.db.commit()
        await self.db.refresh(vuln)
        await self.audit.log(
            "STATUS_CHANGE",
            user_id=actor_id,
            entity_type="vulnerability",
            entity_id=vuln.id,
            details={"old_status": old_status.value, "new_status": vuln.status.value},
        )
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln.id)}})
        if old_status != vuln.status:
            await self._notify_vuln_status_changed(vuln, actor_id)
        return vuln

    async def _notify_vuln_status_changed(self, vuln: Vulnerability, actor_id: int) -> None:
        """Повод №3: статус находки изменился — сообщаем тому, кто её завёл.

        Автору находки, и только если статус менял кто-то другой.
        """
        if vuln.created_by == actor_id:
            return
        status_value = getattr(vuln.status, "value", vuln.status)
        self.db.add(
            Notification(
                user_id=vuln.created_by,
                type=NotificationType.VULN_STATUS_CHANGED,
                vulnerability_id=vuln.id,
                project_id=vuln.project_id,
                actor_id=actor_id,
                status=status_value,
                is_read=False,
            )
        )
        await self.db.commit()
        await ws_manager.notify_user(
            vuln.created_by,
            {
                "event": "notification",
                "entity": "notification",
                "data": {
                    "type": NotificationType.VULN_STATUS_CHANGED.value,
                    "is_read": False,
                    "vulnerability_id": str(vuln.id),
                    "project_id": str(vuln.project_id),
                    "status": status_value,
                },
            },
        )

    async def delete(self, project_id: int, vuln_id: int, actor_id: int) -> None:
        vuln = await self._get_vuln(project_id, vuln_id)
        details = {"project_id": str(project_id), "title": vuln.title, "severity": vuln.severity.value}
        await self.db.delete(vuln)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="vulnerability", entity_id=vuln_id, details=details)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "vulnerability", "project_id": str(project_id), "data": {"id": str(vuln_id)}})

    async def list_assets(self, project_id: int, vuln_id: int) -> list[VulnerabilityAsset]:
        await self._get_vuln(project_id, vuln_id)
        return list((await self.db.scalars(select(VulnerabilityAsset).where(VulnerabilityAsset.vulnerability_id == vuln_id))).all())

    async def _assert_asset_in_project(self, project_id: int, asset_type: AssetType, asset_id: int) -> None:
        if asset_type == AssetType.HOST:
            found = await self.db.scalar(select(Host.id).where(and_(Host.id == asset_id, Host.project_id == project_id)))
        elif asset_type == AssetType.PORT:
            found = await self.db.scalar(
                select(Port.id).join(Host, Port.host_id == Host.id).where(and_(Port.id == asset_id, Host.project_id == project_id))
            )
        elif asset_type == AssetType.SERVICE:
            found = await self.db.scalar(
                select(Service.id)
                .join(Port, Service.port_id == Port.id)
                .join(Host, Port.host_id == Host.id)
                .where(and_(Service.id == asset_id, Host.project_id == project_id))
            )
        else:
            found = await self.db.scalar(
                select(Endpoint.id).join(Host, Endpoint.host_id == Host.id).where(and_(Endpoint.id == asset_id, Host.project_id == project_id))
            )
        if not found:
            raise ValidationError("Актив не найден или принадлежит другому проекту")

    async def add_asset(self, project_id: int, vuln_id: int, asset_type: AssetType, asset_id: int, actor_id: int) -> VulnerabilityAsset:
        await self._get_vuln(project_id, vuln_id)
        await self._assert_asset_in_project(project_id, asset_type, asset_id)
        duplicate = await self.db.scalar(
            select(VulnerabilityAsset).where(
                and_(
                    VulnerabilityAsset.vulnerability_id == vuln_id,
                    VulnerabilityAsset.asset_type == asset_type,
                    VulnerabilityAsset.asset_id == asset_id,
                )
            )
        )
        if duplicate:
            raise ConflictError("Связь уже существует")
        link = VulnerabilityAsset(vulnerability_id=vuln_id, asset_type=asset_type, asset_id=asset_id)
        self.db.add(link)
        await self.db.commit()
        await self.db.refresh(link)
        await self.audit.log("CREATE", user_id=actor_id, entity_type="vulnerability_asset", entity_id=link.id)
        await ws_manager.broadcast(
            project_id,
            {
                "event": "updated",
                "entity": "vulnerability",
                "project_id": str(project_id),
                "data": {"id": str(vuln_id), "asset_link_id": str(link.id)},
            },
        )
        return link

    async def delete_asset(self, project_id: int, vuln_id: int, link_id: int, actor_id: int) -> None:
        await self._get_vuln(project_id, vuln_id)
        link = await self.db.scalar(
            select(VulnerabilityAsset).where(and_(VulnerabilityAsset.id == link_id, VulnerabilityAsset.vulnerability_id == vuln_id))
        )
        if not link:
            raise NotFoundError("Связь не найдена")
        if link.asset_type == AssetType.HOST:
            host_links_count = await self.db.scalar(
                select(func.count())
                .select_from(VulnerabilityAsset)
                .where(and_(VulnerabilityAsset.vulnerability_id == vuln_id, VulnerabilityAsset.asset_type == AssetType.HOST))
            )
            if (host_links_count or 0) <= 1:
                raise ValidationError("Уязвимость должна оставаться привязанной хотя бы к одному хосту")
        await self.db.delete(link)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor_id, entity_type="vulnerability_asset", entity_id=link_id)
        await ws_manager.broadcast(
            project_id,
            {
                "event": "updated",
                "entity": "vulnerability",
                "project_id": str(project_id),
                "data": {"id": str(vuln_id), "asset_link_id": str(link_id)},
            },
        )


class FileService:
    """Сервис загрузки и выдачи файлов уязвимостей."""

    def __init__(self, db: AsyncSession, storage: MinioStorage | None = None) -> None:
        self.db = db
        self.audit = AuditService(db)
        self.storage = storage or MinioStorage()
        self.storage.ensure_bucket()

    async def _ensure_vuln(self, project_id: int, vuln_id: int) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        return vuln

    async def list(self, project_id: int, vuln_id: int) -> list[File]:
        await self._ensure_vuln(project_id, vuln_id)
        return list((await self.db.scalars(select(File).where(File.vulnerability_id == vuln_id).order_by(File.uploaded_at.desc()))).all())

    async def upload(self, project_id: int, vuln_id: int, upload: UploadFile, actor_id: int) -> File:
        await self._ensure_vuln(project_id, vuln_id)
        content = await upload.read()
        if len(content) > MAX_FILE_SIZE:
            raise ValidationError("Размер файла превышает 50 МБ")
        mime_type = magic.from_buffer(content, mime=True)
        if mime_type not in ALLOWED_MIME_TYPES:
            raise ValidationError("Неподдерживаемый тип файла")
        safe_name = _sanitize_filename(upload.filename, fallback="file.bin")
        object_key = await asyncio.to_thread(self.storage.upload_bytes, content, mime_type, safe_name)
        file_meta = File(
            vulnerability_id=vuln_id,
            original_name=safe_name,
            content_type=mime_type,
            size_bytes=len(content),
            minio_bucket=settings.minio_bucket_name,
            minio_key=object_key,
            uploaded_by=actor_id,
        )
        self.db.add(file_meta)
        await self.db.commit()
        await self.db.refresh(file_meta)
        await self.audit.log("FILE_UPLOAD", user_id=actor_id, entity_type="file", entity_id=file_meta.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "file", "project_id": str(project_id), "data": {"id": str(file_meta.id)}})
        return file_meta

    async def download(self, file_id: int, current_user: User) -> tuple[File, bytes]:
        file_meta = await self.db.scalar(select(File).where(File.id == file_id))
        if not file_meta:
            raise NotFoundError("Файл не найден")
        vuln = await self.db.scalar(select(Vulnerability).where(Vulnerability.id == file_meta.vulnerability_id))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        if current_user.role != UserRole.ADMIN:
            membership = await self.db.scalar(
                select(ProjectMember).where(
                    and_(ProjectMember.project_id == vuln.project_id, ProjectMember.user_id == current_user.id)
                )
            )
            if not membership:
                raise ForbiddenError("Нет доступа к файлу")
        blob = await asyncio.to_thread(self.storage.download_bytes, file_meta.minio_key)
        return file_meta, blob

    async def delete(self, project_id: int, vuln_id: int, file_id: int, actor_id: int) -> None:
        await self._ensure_vuln(project_id, vuln_id)
        file_meta = await self.db.scalar(
            select(File).where(and_(File.id == file_id, File.vulnerability_id == vuln_id))
        )
        if not file_meta:
            raise NotFoundError("Файл не найден")
        await self.db.delete(file_meta)
        await self.db.commit()
        await asyncio.to_thread(self.storage.delete, file_meta.minio_key)
        await self.audit.log("FILE_DELETE", user_id=actor_id, entity_type="file", entity_id=file_id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "file", "project_id": str(project_id), "data": {"id": str(file_id)}})


class CommentService:
    """Сервис комментариев и @упоминаний."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _ensure_vuln(self, project_id: int, vuln_id: int) -> Vulnerability:
        vuln = await self.db.scalar(select(Vulnerability).where(and_(Vulnerability.id == vuln_id, Vulnerability.project_id == project_id)))
        if not vuln:
            raise NotFoundError("Уязвимость не найдена")
        return vuln

    async def _extract_mentions(self, project_id: int, content: str) -> list[User]:
        usernames = set(MENTION_RE.findall(content))
        if not usernames:
            return []
        # Принимаем упоминание, если юзер либо участник проекта, либо админ
        # (админы имеют доступ ко всем проектам без явного членства, поэтому
        # упоминание их в комментарии тоже должно создавать уведомление).
        # В outer-join'е на пару (user, project) каждая уникальная связь даёт
        # ровно одну строку из-за UNIQUE constraint ProjectMember(project_id, user_id),
        # а юзеры без membership дают по одной строке с NULL membership.
        rows = (
            await self.db.scalars(
                select(User)
                .outerjoin(ProjectMember, and_(ProjectMember.user_id == User.id, ProjectMember.project_id == project_id))
                .where(
                    and_(
                        User.username.in_(list(usernames)),
                        or_(ProjectMember.user_id.is_not(None), User.role == UserRole.ADMIN),
                    )
                )
            )
        ).all()
        return list(rows)

    async def list(self, vuln_id: int, page: int, size: int) -> tuple[list[CommentOut], int]:
        total = await self.db.scalar(select(func.count()).select_from(Comment).where(Comment.vulnerability_id == vuln_id)) or 0
        rows = (
            await self.db.execute(
                select(Comment, User)
                .join(User, User.id == Comment.user_id)
                .where(Comment.vulnerability_id == vuln_id)
                .order_by(Comment.created_at.asc())
                .offset((page - 1) * size)
                .limit(size)
            )
        ).all()
        result: list[CommentOut] = []
        for comment, user in rows:
            mention_rows = (
                await self.db.execute(
                    select(CommentMention, User)
                    .join(User, User.id == CommentMention.user_id)
                    .where(CommentMention.comment_id == comment.id)
                )
            ).all()
            mentions = [MentionOut(user_id=u.id, username=u.username) for _, u in mention_rows]
            result.append(
                CommentOut(
                    id=comment.id,
                    vulnerability_id=comment.vulnerability_id,
                    user_id=comment.user_id,
                    username=user.username,
                    avatar_url=user.avatar_url,
                    content=comment.content,
                    mentions=mentions,
                    created_at=comment.created_at,
                    updated_at=comment.updated_at,
                )
            )
        return result, total

    async def create(self, project_id: int, vuln_id: int, content: str, actor: User) -> CommentOut:
        vuln = await self._ensure_vuln(project_id, vuln_id)
        comment = Comment(vulnerability_id=vuln.id, user_id=actor.id, content=content)
        self.db.add(comment)
        await self.db.flush()
        mentioned_users = await self._extract_mentions(project_id, content)
        mention_models: list[MentionOut] = []
        for user in mentioned_users:
            self.db.add(CommentMention(comment_id=comment.id, user_id=user.id))
            # Упоминание себя подсвечиваем в тексте, но не уведомляем: человек
            # только что сам это и написал.
            if user.id != actor.id:
                self.db.add(
                    Notification(
                        user_id=user.id,
                        type=NotificationType.MENTION,
                        comment_id=comment.id,
                        actor_id=actor.id,
                        is_read=False,
                    )
                )
            mention_models.append(MentionOut(user_id=user.id, username=user.username))
        await self.db.commit()
        await self.db.refresh(comment)
        for user in mentioned_users:
            if user.id == actor.id:
                continue
            await ws_manager.notify_user(
                user.id,
                {
                    "event": "notification",
                    "entity": "notification",
                    "data": {
                        "type": NotificationType.MENTION.value,
                        "is_read": False,
                        "comment_id": str(comment.id),
                        "vulnerability_id": str(vuln.id),
                        "vulnerability_title": vuln.title,
                        "project_id": str(project_id),
                        "commenter_username": actor.username,
                    },
                },
            )
        await self.audit.log("CREATE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "created", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})
        return CommentOut(
            id=comment.id,
            vulnerability_id=comment.vulnerability_id,
            user_id=comment.user_id,
            username=actor.username,
            avatar_url=actor.avatar_url,
            content=comment.content,
            mentions=mention_models,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def update(self, project_id: int, vuln_id: int, comment_id: int, content: str, actor: User) -> CommentOut:
        await self._ensure_vuln(project_id, vuln_id)
        comment = await self.db.scalar(
            select(Comment).where(and_(Comment.id == comment_id, Comment.vulnerability_id == vuln_id))
        )
        if not comment:
            raise NotFoundError("Комментарий не найден")
        if comment.user_id != actor.id:
            raise ForbiddenError("Можно редактировать только свой комментарий")
        comment.content = content
        await self.db.execute(delete(CommentMention).where(CommentMention.comment_id == comment.id))
        mentioned_users = await self._extract_mentions(project_id, content)
        mention_models: list[MentionOut] = []
        for user in mentioned_users:
            self.db.add(CommentMention(comment_id=comment.id, user_id=user.id))
            mention_models.append(MentionOut(user_id=user.id, username=user.username))
        await self.db.commit()
        await self.db.refresh(comment)
        await self.audit.log("UPDATE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})
        return CommentOut(
            id=comment.id,
            vulnerability_id=comment.vulnerability_id,
            user_id=comment.user_id,
            username=actor.username,
            avatar_url=actor.avatar_url,
            content=comment.content,
            mentions=mention_models,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def delete(self, project_id: int, vuln_id: int, comment_id: int, actor: User) -> None:
        await self._ensure_vuln(project_id, vuln_id)
        comment = await self.db.scalar(
            select(Comment).where(and_(Comment.id == comment_id, Comment.vulnerability_id == vuln_id))
        )
        if not comment:
            raise NotFoundError("Комментарий не найден")
        if comment.user_id != actor.id:
            raise ForbiddenError("Можно удалить только свой комментарий")
        await self.db.delete(comment)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor.id, entity_type="comment", entity_id=comment.id)
        await ws_manager.broadcast(project_id, {"event": "deleted", "entity": "comment", "project_id": str(project_id), "data": {"id": str(comment.id)}})


class ProjectNoteService:
    """Сервис управления страницами заметок проекта и их комментариями."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _ensure_project(self, project_id: int) -> Project:
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        return project

    async def _get_note(self, project_id: int, note_id: int) -> ProjectNote:
        note = await self.db.scalar(select(ProjectNote).where(and_(ProjectNote.id == note_id, ProjectNote.project_id == project_id)))
        if not note:
            raise NotFoundError("Страница заметки не найдена")
        return note

    async def _ensure_parent(self, project_id: int, parent_id: int | None) -> ProjectNote | None:
        if not parent_id:
            return None
        parent = await self.db.scalar(
            select(ProjectNote).where(and_(ProjectNote.id == parent_id, ProjectNote.project_id == project_id))
        )
        if not parent:
            raise NotFoundError("Родительская страница не найдена")
        return parent

    async def _ensure_unique_title(
        self,
        project_id: int,
        parent_id: int | None,
        title: str,
        *,
        exclude_note_id: int | None = None,
    ) -> None:
        query = select(ProjectNote).where(
            and_(
                ProjectNote.project_id == project_id,
                ProjectNote.title == title,
                ProjectNote.parent_id.is_(None) if parent_id is None else ProjectNote.parent_id == parent_id,
            )
        )
        if exclude_note_id:
            query = query.where(ProjectNote.id != exclude_note_id)
        duplicate = await self.db.scalar(query)
        if duplicate:
            raise ConflictError("В этом разделе уже есть страница с таким названием")

    async def _next_sort_order(self, project_id: int, parent_id: int | None) -> int:
        max_sort = await self.db.scalar(
            select(func.max(ProjectNote.sort_order)).where(
                and_(
                    ProjectNote.project_id == project_id,
                    ProjectNote.parent_id.is_(None) if parent_id is None else ProjectNote.parent_id == parent_id,
                )
            )
        )
        return int(max_sort or 0) + 1

    async def _ensure_not_descendant_move(self, project_id: int, note_id: int, new_parent_id: int | None) -> None:
        cursor = new_parent_id
        visited: set[int] = set()
        while cursor is not None:
            if cursor == note_id:
                raise ValidationError("Нельзя переместить страницу в её дочернюю страницу")
            if cursor in visited:
                raise ValidationError("Обнаружен цикл в дереве заметок")
            visited.add(cursor)
            parent = await self.db.scalar(
                select(ProjectNote.parent_id).where(and_(ProjectNote.id == cursor, ProjectNote.project_id == project_id))
            )
            cursor = parent

    async def list_notes(self, project_id: int) -> list[ProjectNote]:
        await self._ensure_project(project_id)
        rows = await self.db.scalars(
            select(ProjectNote)
            .where(ProjectNote.project_id == project_id)
            .order_by(ProjectNote.parent_id.asc().nullsfirst(), ProjectNote.sort_order.asc(), ProjectNote.title.asc())
        )
        return list(rows.all())

    async def list_activity(self, project_id: int, limit: int = 30) -> list[dict]:
        """Журнал CREATE/UPDATE/DELETE действий с заметками этого проекта.

        Подцепляем audit-записи двумя путями, чтобы покрыть и новые, и старые
        записи журнала:
          1) details.project_id == project_id — новый формат (после миграции UI):
             единственный надёжный способ узнать проект для DELETE-записей,
             где самой заметки уже нет в БД.
          2) entity_id IN (заметки этого проекта) — fallback для старых
             CREATE/UPDATE записей без project_id в details.
        Title берём из details или из самой заметки (если она ещё жива).
        Username — через outer join к users (может быть NULL для удалённых).
        """
        await self._ensure_project(project_id)
        # Подзапрос ID заметок текущего проекта — для fallback по entity_id.
        project_note_ids = select(ProjectNote.id).where(ProjectNote.project_id == project_id)
        stmt = (
            select(AuditLog, User.username, ProjectNote.title)
            .outerjoin(User, User.id == AuditLog.user_id)
            .outerjoin(ProjectNote, ProjectNote.id == AuditLog.entity_id)
            .where(AuditLog.entity_type == "project_note")
            .where(AuditLog.action.in_(("CREATE", "UPDATE", "DELETE")))
            .where(
                or_(
                    AuditLog.details["project_id"].as_string() == str(project_id),
                    AuditLog.entity_id.in_(project_note_ids),
                )
            )
            .order_by(AuditLog.created_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        out: list[dict] = []
        for entry, username, note_title in rows:
            details = entry.details or {}
            # Приоритет: title из details (сохранён при удалении) → текущий title из БД.
            title = details.get("title") or note_title
            out.append(
                {
                    "id": entry.id,
                    "action": entry.action,
                    "note_id": entry.entity_id,
                    "note_title": title,
                    "user_id": entry.user_id,
                    "username": username,
                    "created_at": entry.created_at.isoformat() if entry.created_at else None,
                }
            )
        return out

    async def get_note(self, project_id: int, note_id: int) -> ProjectNote:
        return await self._get_note(project_id, note_id)

    async def create_note(self, project_id: int, payload: dict, actor_id: int) -> ProjectNote:
        await self._ensure_project(project_id)
        title = str(payload["title"]).strip()
        parent_id = payload.get("parent_id")
        content = payload.get("content")
        await self._ensure_parent(project_id, parent_id)
        await self._ensure_unique_title(project_id, parent_id, title)
        note = ProjectNote(
            project_id=project_id,
            parent_id=parent_id,
            title=title,
            content=content,
            sort_order=await self._next_sort_order(project_id, parent_id),
            created_by=actor_id,
            updated_by=actor_id,
        )
        self.db.add(note)
        await self.db.commit()
        await self.db.refresh(note)
        # project_id и title в details — нужны для post-факта журнала активности
        # уровня проекта (DELETE-записи без них нельзя было бы связать с проектом).
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="project_note",
            entity_id=note.id,
            details={"project_id": str(project_id), "title": note.title},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "created", "entity": "project_note", "project_id": str(project_id), "data": {"id": str(note.id)}},
        )
        return note

    async def update_note(self, project_id: int, note_id: int, payload: dict, actor_id: int) -> ProjectNote:
        note = await self._get_note(project_id, note_id)
        next_title = payload.get("title")
        if next_title is not None:
            normalized_title = str(next_title).strip()
            if normalized_title != note.title:
                await self._ensure_unique_title(project_id, note.parent_id, normalized_title, exclude_note_id=note.id)
                note.title = normalized_title
        if "content" in payload:
            note.content = payload.get("content")
        note.updated_by = actor_id
        await self.db.commit()
        await self.db.refresh(note)
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="project_note",
            entity_id=note.id,
            details={"project_id": str(project_id), "title": note.title},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "updated", "entity": "project_note", "project_id": str(project_id), "data": {"id": str(note.id)}},
        )
        return note

    async def move_note(self, project_id: int, note_id: int, parent_id: int | None, actor_id: int) -> ProjectNote:
        note = await self._get_note(project_id, note_id)
        if parent_id == note.id:
            raise ValidationError("Нельзя переместить страницу в саму себя")
        await self._ensure_parent(project_id, parent_id)
        await self._ensure_not_descendant_move(project_id, note.id, parent_id)
        await self._ensure_unique_title(project_id, parent_id, note.title, exclude_note_id=note.id)
        note.parent_id = parent_id
        note.sort_order = await self._next_sort_order(project_id, parent_id)
        note.updated_by = actor_id
        await self.db.commit()
        await self.db.refresh(note)
        await self.audit.log("UPDATE", user_id=actor_id, entity_type="project_note", entity_id=note.id, details={"action": "move"})
        await ws_manager.broadcast(
            project_id,
            {"event": "updated", "entity": "project_note", "project_id": str(project_id), "data": {"id": str(note.id)}},
        )
        return note

    async def reorder_notes(self, project_id: int, parent_id: int | None, items: list[dict], actor_id: int) -> list[ProjectNote]:
        await self._ensure_parent(project_id, parent_id)
        siblings = (
            await self.db.scalars(
                select(ProjectNote).where(
                    and_(
                        ProjectNote.project_id == project_id,
                        ProjectNote.parent_id.is_(None) if parent_id is None else ProjectNote.parent_id == parent_id,
                    )
                )
            )
        ).all()
        sibling_map = {item.id: item for item in siblings}
        item_ids = {entry["id"] for entry in items}
        if item_ids != set(sibling_map.keys()):
            raise ValidationError("Для ручной сортировки нужно передать полный набор sibling-страниц")
        for entry in items:
            note = sibling_map[entry["id"]]
            note.sort_order = int(entry["sort_order"])
            note.updated_by = actor_id
        await self.db.commit()
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="project_note",
            details={"action": "reorder", "parent_id": str(parent_id) if parent_id else None},
        )
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "project_note", "project_id": str(project_id)})
        updated = (
            await self.db.scalars(
                select(ProjectNote).where(
                    and_(
                        ProjectNote.project_id == project_id,
                        ProjectNote.parent_id.is_(None) if parent_id is None else ProjectNote.parent_id == parent_id,
                    )
                ).order_by(ProjectNote.sort_order.asc(), ProjectNote.title.asc())
            )
        ).all()
        return list(updated)

    async def delete_note(self, project_id: int, note_id: int, actor_id: int) -> None:
        note = await self._get_note(project_id, note_id)
        deleted_title = note.title  # запоминаем заголовок ДО удаления для журнала
        await self.db.delete(note)
        await self.db.commit()
        await self.audit.log(
            "DELETE",
            user_id=actor_id,
            entity_type="project_note",
            entity_id=note_id,
            details={"project_id": str(project_id), "title": deleted_title},
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "deleted", "entity": "project_note", "project_id": str(project_id), "data": {"id": str(note_id)}},
        )

    async def _get_comment(self, project_id: int, note_id: int, comment_id: int) -> ProjectNoteComment:
        comment = await self.db.scalar(
            select(ProjectNoteComment).where(
                and_(
                    ProjectNoteComment.id == comment_id,
                    ProjectNoteComment.note_id == note_id,
                    ProjectNoteComment.project_id == project_id,
                )
            )
        )
        if not comment:
            raise NotFoundError("Комментарий не найден")
        return comment

    async def list_comments(self, project_id: int, note_id: int, page: int, size: int) -> tuple[list[ProjectNoteCommentOut], int]:
        await self._get_note(project_id, note_id)
        total = await self.db.scalar(
            select(func.count()).select_from(ProjectNoteComment).where(
                and_(ProjectNoteComment.project_id == project_id, ProjectNoteComment.note_id == note_id)
            )
        ) or 0
        rows = (
            await self.db.execute(
                select(ProjectNoteComment, User)
                .join(User, User.id == ProjectNoteComment.user_id)
                .where(and_(ProjectNoteComment.project_id == project_id, ProjectNoteComment.note_id == note_id))
                .order_by(ProjectNoteComment.created_at.asc())
                .offset((page - 1) * size)
                .limit(size)
            )
        ).all()
        return (
            [
                ProjectNoteCommentOut(
                    id=comment.id,
                    project_id=comment.project_id,
                    note_id=comment.note_id,
                    user_id=comment.user_id,
                    username=user.username,
                    avatar_url=user.avatar_url,
                    content=comment.content,
                    created_at=comment.created_at,
                    updated_at=comment.updated_at,
                )
                for comment, user in rows
            ],
            int(total),
        )

    async def create_comment(self, project_id: int, note_id: int, content: str, actor: User) -> ProjectNoteCommentOut:
        note = await self._get_note(project_id, note_id)
        comment = ProjectNoteComment(project_id=project_id, note_id=note.id, user_id=actor.id, content=content)
        self.db.add(comment)
        await self.db.flush()
        # Уведомления @username (упоминания) — тот же экстрактор, что у уязвимостей.
        # Создаём Notification с note_comment_id (а не comment_id), чтобы NotificationService
        # знал, что это упоминание в заметке и подгрузил соответствующий контекст.
        # Себя не уведомляем: автор комментария и так знает, что написал.
        mentioned_users = [u for u in await CommentService(self.db)._extract_mentions(project_id, content) if u.id != actor.id]
        for user in mentioned_users:
            self.db.add(
                Notification(
                    user_id=user.id,
                    type=NotificationType.MENTION,
                    note_comment_id=comment.id,
                    actor_id=actor.id,
                    is_read=False,
                )
            )
        await self.db.commit()
        await self.db.refresh(comment)
        for user in mentioned_users:
            await ws_manager.notify_user(
                user.id,
                {
                    "event": "notification",
                    "entity": "notification",
                    "data": {
                        "type": NotificationType.MENTION.value,
                        "is_read": False,
                        "note_comment_id": str(comment.id),
                        "note_id": str(note.id),
                        "note_title": note.title,
                        "project_id": str(project_id),
                        "commenter_username": actor.username,
                    },
                },
            )
        await self.audit.log("CREATE", user_id=actor.id, entity_type="project_note_comment", entity_id=comment.id)
        await ws_manager.broadcast(
            project_id,
            {
                "event": "created",
                "entity": "project_note_comment",
                "project_id": str(project_id),
                "data": {"id": str(comment.id), "note_id": str(note.id)},
            },
        )
        return ProjectNoteCommentOut(
            id=comment.id,
            project_id=comment.project_id,
            note_id=comment.note_id,
            user_id=comment.user_id,
            username=actor.username,
            avatar_url=actor.avatar_url,
            content=comment.content,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def update_comment(
        self,
        project_id: int,
        note_id: int,
        comment_id: int,
        content: str,
        actor: User,
    ) -> ProjectNoteCommentOut:
        comment = await self._get_comment(project_id, note_id, comment_id)
        if comment.user_id != actor.id:
            raise ForbiddenError("Можно редактировать только свой комментарий")
        comment.content = content
        await self.db.commit()
        await self.db.refresh(comment)
        await self.audit.log("UPDATE", user_id=actor.id, entity_type="project_note_comment", entity_id=comment.id)
        await ws_manager.broadcast(
            project_id,
            {
                "event": "updated",
                "entity": "project_note_comment",
                "project_id": str(project_id),
                "data": {"id": str(comment.id), "note_id": str(note_id)},
            },
        )
        return ProjectNoteCommentOut(
            id=comment.id,
            project_id=comment.project_id,
            note_id=comment.note_id,
            user_id=comment.user_id,
            username=actor.username,
            avatar_url=actor.avatar_url,
            content=comment.content,
            created_at=comment.created_at,
            updated_at=comment.updated_at,
        )

    async def delete_comment(self, project_id: int, note_id: int, comment_id: int, actor: User) -> None:
        comment = await self._get_comment(project_id, note_id, comment_id)
        if comment.user_id != actor.id:
            raise ForbiddenError("Можно удалить только свой комментарий")
        await self.db.delete(comment)
        await self.db.commit()
        await self.audit.log("DELETE", user_id=actor.id, entity_type="project_note_comment", entity_id=comment.id)
        await ws_manager.broadcast(
            project_id,
            {
                "event": "deleted",
                "entity": "project_note_comment",
                "project_id": str(project_id),
                "data": {"id": str(comment.id), "note_id": str(note_id)},
            },
        )


class ProjectCredentialService:
    """Хранилище учётных данных проекта (аккаунты и токены).

    Секрет (пароль/токен) шифруется перед записью и расшифровывается при выдаче
    участникам проекта — доступ к чтению совпадает с доступом к проекту
    (`require_project_access`), как у заметок.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.audit = AuditService(db)

    async def _ensure_project(self, project_id: int) -> Project:
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        return project

    async def _get_credential(self, project_id: int, credential_id: int) -> ProjectCredential:
        credential = await self.db.scalar(
            select(ProjectCredential).where(
                and_(ProjectCredential.id == credential_id, ProjectCredential.project_id == project_id)
            )
        )
        if not credential:
            raise NotFoundError("Учётные данные не найдены")
        return credential

    @staticmethod
    def _serialize(credential: ProjectCredential) -> dict:
        """Отдаёт креды с расшифрованным паролем (для ProjectCredentialOut)."""
        return {
            "id": credential.id,
            "project_id": credential.project_id,
            "username": credential.username,
            "password": decrypt_secret(credential.password_encrypted),
            "host": credential.host,
            "created_by": credential.created_by,
            "created_by_username": credential.created_by_username,
            "created_at": credential.created_at,
            "updated_at": credential.updated_at,
        }

    async def list_credentials(self, project_id: int) -> list[dict]:
        await self._ensure_project(project_id)
        rows = await self.db.scalars(
            select(ProjectCredential)
            .where(ProjectCredential.project_id == project_id)
            .order_by(ProjectCredential.created_at.asc(), ProjectCredential.id.asc())
        )
        return [self._serialize(row) for row in rows.all()]

    async def create_credential(self, project_id: int, payload: dict, actor_id: int) -> dict:
        await self._ensure_project(project_id)
        credential = ProjectCredential(
            project_id=project_id,
            username=payload.get("username"),
            password_encrypted=encrypt_secret(str(payload["password"])),
            host=payload.get("host"),
            created_by=actor_id,
        )
        self.db.add(credential)
        await self.db.commit()
        await self.db.refresh(credential)
        # В журнал пишем только метаданные (username/host для строки ленты) —
        # пароль в аудит не попадает.
        await self.audit.log(
            "CREATE",
            user_id=actor_id,
            entity_type="project_credential",
            entity_id=credential.id,
            details={"project_id": str(project_id), "username": credential.username, "host": credential.host},
        )
        return self._serialize(credential)

    async def update_credential(self, project_id: int, credential_id: int, payload: dict, actor_id: int) -> dict:
        credential = await self._get_credential(project_id, credential_id)
        if "username" in payload:
            credential.username = payload.get("username")
        if "host" in payload:
            credential.host = payload.get("host")
        # Пустой/отсутствующий password означает «не менять» — форма редактирования
        # не присылает существующий пароль обратно, чтобы его не логировать/светить.
        if payload.get("password"):
            credential.password_encrypted = encrypt_secret(str(payload["password"]))
        await self.db.commit()
        await self.db.refresh(credential)
        await self.audit.log(
            "UPDATE",
            user_id=actor_id,
            entity_type="project_credential",
            entity_id=credential.id,
            details={"project_id": str(project_id), "username": credential.username, "host": credential.host},
        )
        return self._serialize(credential)

    async def delete_credential(self, project_id: int, credential_id: int, actor_id: int) -> None:
        credential = await self._get_credential(project_id, credential_id)
        username = credential.username
        host = credential.host
        await self.db.delete(credential)
        await self.db.commit()
        await self.audit.log(
            "DELETE",
            user_id=actor_id,
            entity_type="project_credential",
            entity_id=credential_id,
            details={"project_id": str(project_id), "username": username, "host": host},
        )


class NotificationService:
    """Сервис уведомлений пользователя."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _context_for_event(self, item: Notification) -> NotificationContext | None:
        """Контекст уведомлений, не связанных с комментарием.

        Это добавление в проект и смены статусов: предмет записан прямо в
        notification (project_id / vulnerability_id), названия и имя инициатора
        подтягиваем здесь.
        """
        if item.project_id is None and item.vulnerability_id is None:
            return None
        actor_username = None
        if item.actor_id:
            actor_username = await self.db.scalar(select(User.username).where(User.id == item.actor_id))
        project_id = item.project_id
        vuln_title = None
        if item.vulnerability_id:
            row = (
                await self.db.execute(
                    select(Vulnerability.title, Vulnerability.project_id).where(Vulnerability.id == item.vulnerability_id)
                )
            ).first()
            if row:
                vuln_title, project_id = row
        project_name = await self.db.scalar(select(Project.name).where(Project.id == project_id)) if project_id else None
        return NotificationContext(
            vulnerability_id=item.vulnerability_id,
            vulnerability_title=vuln_title,
            project_id=project_id,
            project_name=project_name,
            commenter_username=actor_username,
            status=item.status,
        )

    async def list(self, user_id: int, page: int, size: int, is_read: bool | None) -> tuple[list[NotificationOut], int]:
        query = select(Notification).where(Notification.user_id == user_id)
        if is_read is not None:
            query = query.where(Notification.is_read == is_read)
        total = await self.db.scalar(select(func.count()).select_from(query.subquery())) or 0
        notifications = (
            await self.db.scalars(query.order_by(Notification.created_at.desc()).offset((page - 1) * size).limit(size))
        ).all()
        result: list[NotificationOut] = []
        for item in notifications:
            context = None
            if item.comment_id:
                host_id = await self.db.scalar(
                    select(VulnerabilityAsset.asset_id)
                    .join(Vulnerability, Vulnerability.id == VulnerabilityAsset.vulnerability_id)
                    .where(
                        and_(
                            VulnerabilityAsset.asset_type == AssetType.HOST,
                            Vulnerability.id
                            == select(Comment.vulnerability_id).where(Comment.id == item.comment_id).scalar_subquery(),
                        )
                    )
                    .limit(1)
                )
                row = await self.db.execute(
                    select(Comment, Vulnerability, User)
                    .join(Vulnerability, Vulnerability.id == Comment.vulnerability_id)
                    .join(User, User.id == Comment.user_id)
                    .where(Comment.id == item.comment_id)
                )
                data = row.first()
                if data:
                    comment, vuln, commenter = data
                    context = NotificationContext(
                        vulnerability_id=vuln.id,
                        vulnerability_title=vuln.title,
                        project_id=vuln.project_id,
                        host_id=host_id,
                        commenter_username=commenter.username,
                    )
            elif item.note_comment_id:
                # Контекст для упоминания в комментарии заметки: подгружаем сам комментарий,
                # заметку (для названия) и автора (для commenter_username).
                row = await self.db.execute(
                    select(ProjectNoteComment, ProjectNote, User)
                    .join(ProjectNote, ProjectNote.id == ProjectNoteComment.note_id)
                    .join(User, User.id == ProjectNoteComment.user_id)
                    .where(ProjectNoteComment.id == item.note_comment_id)
                )
                data = row.first()
                if data:
                    note_comment, note, commenter = data
                    context = NotificationContext(
                        note_id=note.id,
                        note_title=note.title,
                        project_id=note.project_id,
                        commenter_username=commenter.username,
                    )
            else:
                # Уведомления о проекте и статусах: предмет лежит прямо на записи,
                # названия подтягиваем сейчас, чтобы фронт не ходил за ними отдельно.
                context = await self._context_for_event(item)
            result.append(
                NotificationOut(
                    id=item.id,
                    type=item.type.value,
                    comment_id=item.comment_id,
                    note_comment_id=item.note_comment_id,
                    is_read=item.is_read,
                    created_at=item.created_at,
                    context=context,
                )
            )
        return result, total

    async def unread_count(self, user_id: int) -> int:
        return await self.db.scalar(
            select(func.count()).select_from(Notification).where(and_(Notification.user_id == user_id, Notification.is_read.is_(False)))
        ) or 0

    async def mark_read(self, notification_id: int, user_id: int) -> Notification:
        notification = await self.db.scalar(
            select(Notification).where(and_(Notification.id == notification_id, Notification.user_id == user_id))
        )
        if not notification:
            raise NotFoundError("Уведомление не найдено")
        notification.is_read = True
        await self.db.commit()
        await self.db.refresh(notification)
        return notification

    async def mark_all_read(self, user_id: int) -> None:
        await self.db.execute(update(Notification).where(Notification.user_id == user_id).values(is_read=True))
        await self.db.commit()


class ImportService:
    """Сервис импорта инфраструктуры из JSON-формата PCF."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def _find_matching_host(self, project_id: int, host_data) -> Host | None:
        clauses = []
        if host_data.ip_address:
            clauses.append(Host.ip_address == host_data.ip_address)
        if host_data.hostname:
            clauses.append(Host.hostname == host_data.hostname)
        if not clauses:
            return None
        matches = list(
            (
                await self.db.scalars(
                    select(Host).where(and_(Host.project_id == project_id, or_(*clauses)))
                )
            ).all()
        )
        if not matches:
            return None
        exact_matches = [
            host for host in matches if host.ip_address == host_data.ip_address and host.hostname == host_data.hostname
        ]
        if exact_matches:
            return exact_matches[0]
        if len(matches) == 1:
            return matches[0]
        raise ValidationError(
            f"Найдено несколько host для ip/hostname ({host_data.ip_address or '-'} / {host_data.hostname or '-'})"
        )

    @staticmethod
    def _merge_host_fields(host: Host, host_data) -> None:
        if not host.ip_address and host_data.ip_address:
            host.ip_address = host_data.ip_address
        if not host.hostname and host_data.hostname:
            host.hostname = host_data.hostname
        if host.status.value == "unknown" and host_data.status.value != "unknown":
            host.status = host_data.status
        if not host.notes and host_data.notes:
            host.notes = host_data.notes

    @staticmethod
    def _merge_service_fields(service: Service, service_data) -> None:
        if not service.version and service_data.version:
            service.version = service_data.version
        if not service.banner and service_data.banner:
            service.banner = service_data.banner

    @staticmethod
    def _merge_endpoint_fields(endpoint: Endpoint, endpoint_payload: dict) -> None:
        if not endpoint.description and endpoint_payload.get("description"):
            endpoint.description = endpoint_payload["description"]
        if not endpoint.query_params and endpoint_payload.get("query_params"):
            endpoint.query_params = endpoint_payload["query_params"]
        if not endpoint.request_body and endpoint_payload.get("request_body"):
            endpoint.request_body = endpoint_payload["request_body"]
        if not endpoint.request_content_type and endpoint_payload.get("request_content_type"):
            endpoint.request_content_type = endpoint_payload["request_content_type"]
        if not endpoint.request_headers and endpoint_payload.get("request_headers"):
            endpoint.request_headers = endpoint_payload["request_headers"]

    @staticmethod
    def _decode_text_payload(payload: bytes) -> str:
        try:
            return payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValidationError("Файл должен быть в кодировке UTF-8") from exc

    @staticmethod
    def _validate_openapi_payload(payload: bytes) -> None:
        if not payload:
            raise ValidationError("Swagger/OpenAPI файл пуст")
        if len(payload) > MAX_OPENAPI_IMPORT_BYTES:
            raise ValidationError("Swagger/OpenAPI файл превышает 2 МБ")

    @staticmethod
    def _parse_relaxed_openapi_scalar(raw_value: str) -> object:
        value = raw_value.strip().rstrip(",").strip()
        if not value:
            return ""
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if re.fullmatch(r"-?\d+", value):
            try:
                return int(value)
            except ValueError:
                return value
        return value

    @classmethod
    def _parse_relaxed_openapi_object(cls, lines: list[str], index: int) -> tuple[dict, int]:
        result: dict = {}
        while index < len(lines):
            line = lines[index].strip()
            if not line:
                index += 1
                continue
            normalized = line[:-1].rstrip() if line.endswith(",") else line
            if normalized == "}":
                return result, index + 1
            if normalized.endswith("{"):
                key = normalized[:-1].strip()
                nested, index = cls._parse_relaxed_openapi_object(lines, index + 1)
                result[key] = nested
                continue
            if normalized.endswith("["):
                key = normalized[:-1].strip()
                nested, index = cls._parse_relaxed_openapi_array(lines, index + 1)
                result[key] = nested
                continue
            parts = normalized.split(None, 1)
            key = parts[0].strip()
            raw_value = parts[1] if len(parts) > 1 else ""
            if raw_value == "{}":
                result[key] = {}
            elif raw_value == "[]":
                result[key] = []
            else:
                result[key] = cls._parse_relaxed_openapi_scalar(raw_value)
            index += 1
        return result, index

    @classmethod
    def _parse_relaxed_openapi_array(cls, lines: list[str], index: int) -> tuple[list[object], int]:
        result: list[object] = []
        while index < len(lines):
            line = lines[index].strip()
            if not line:
                index += 1
                continue
            normalized = line[:-1].rstrip() if line.endswith(",") else line
            if normalized == "]":
                return result, index + 1
            if normalized == "{":
                nested, index = cls._parse_relaxed_openapi_object(lines, index + 1)
                result.append(nested)
                continue
            if normalized == "[":
                nested, index = cls._parse_relaxed_openapi_array(lines, index + 1)
                result.append(nested)
                continue
            result.append(cls._parse_relaxed_openapi_scalar(normalized))
            index += 1
        return result, index

    @staticmethod
    def _normalize_relaxed_openapi_mime(value: str) -> str:
        text = value.strip()
        if "/" in text:
            return text
        for prefix in ("application", "multipart", "text", "image", "audio", "video"):
            if text.startswith(prefix) and len(text) > len(prefix):
                return f"{prefix}/{text[len(prefix):]}"
        return text

    @staticmethod
    def _normalize_relaxed_openapi_ref(value: str) -> str:
        text = value.strip()
        for prefix in ("definitions", "parameters", "responses", "securityDefinitions"):
            compact = f"#{prefix}"
            if text.startswith(compact) and not text.startswith(f"#/{prefix}/"):
                tail = text[len(compact) :].strip("/")
                if tail:
                    return f"#/{prefix}/{tail}"
        return text

    @classmethod
    def _normalize_relaxed_openapi_path_key(cls, raw_path: str, path_item: object) -> str:
        text = str(raw_path or "").strip()
        if not text:
            return "/"
        if text.startswith("/"):
            return text
        first_tag = ""
        if isinstance(path_item, dict):
            for operation in path_item.values():
                if not isinstance(operation, dict):
                    continue
                tags = operation.get("tags")
                if isinstance(tags, list) and tags:
                    candidate = str(tags[0] or "").strip().strip("/")
                    if candidate:
                        first_tag = candidate
                        break
        if first_tag and text.lower().startswith(first_tag.lower()):
            tail = text[len(first_tag) :].lstrip("/")
            text = f"/{first_tag}/{tail}" if tail else f"/{first_tag}"
        else:
            text = f"/{text.lstrip('/')}"
        text = re.sub(r"(?<!/)\{", "/{", text)
        text = re.sub(r"\}(?!/|$)", "}/", text)
        text = re.sub(r"/{2,}", "/", text)
        return text

    @classmethod
    def _normalize_relaxed_openapi_document(cls, value: object, key: str | None = None) -> object:
        if isinstance(value, dict):
            normalized = {item_key: cls._normalize_relaxed_openapi_document(item_value, item_key) for item_key, item_value in value.items()}
            if "basePath" in normalized and isinstance(normalized["basePath"], str):
                base_path = normalized["basePath"].strip()
                normalized["basePath"] = f"/{base_path.lstrip('/')}" if base_path else ""
            if "paths" in normalized and isinstance(normalized["paths"], dict):
                normalized["paths"] = {
                    cls._normalize_relaxed_openapi_path_key(path_key, path_item): path_item
                    for path_key, path_item in normalized["paths"].items()
                }
            return normalized
        if isinstance(value, list):
            return [cls._normalize_relaxed_openapi_document(item, key) for item in value]
        if isinstance(value, str):
            text = value.strip()
            if key == "$ref":
                return cls._normalize_relaxed_openapi_ref(text)
            if key in {"consumes", "produces"}:
                return cls._normalize_relaxed_openapi_mime(text)
            return text
        return value

    @classmethod
    def _load_relaxed_openapi_document(cls, raw_text: str) -> dict:
        lines = raw_text.splitlines()
        index = 0
        while index < len(lines) and not lines[index].strip():
            index += 1
        if index >= len(lines) or lines[index].strip() != "{":
            raise ValidationError("Swagger/OpenAPI файл должен быть валидным JSON или YAML")
        parsed, next_index = cls._parse_relaxed_openapi_object(lines, index + 1)
        trailing = [line.strip() for line in lines[next_index:] if line.strip()]
        if trailing:
            raise ValidationError("Swagger/OpenAPI файл должен быть валидным JSON или YAML")
        normalized = cls._normalize_relaxed_openapi_document(parsed)
        if not isinstance(normalized, dict):
            raise ValidationError("Swagger/OpenAPI документ должен быть объектом")
        return normalized

    @classmethod
    def _load_json_or_yaml_document(cls, raw_text: str) -> dict:
        if not raw_text.strip():
            raise ValidationError("Swagger/OpenAPI файл пуст")
        try:
            parsed = json.loads(raw_text)
        except Exception:
            try:
                parsed = yaml.safe_load(raw_text)
            except Exception as exc:
                try:
                    parsed = cls._load_relaxed_openapi_document(raw_text)
                except Exception:
                    raise ValidationError("Swagger/OpenAPI файл должен быть валидным JSON или YAML") from exc
        if not isinstance(parsed, dict):
            raise ValidationError("Swagger/OpenAPI документ должен быть объектом")
        return parsed

    @staticmethod
    def _resolve_json_pointer(document: dict, ref: str) -> object:
        if not ref.startswith("#/"):
            raise ValidationError("Поддерживаются только локальные $ref вида '#/...'")
        current: object = document
        for raw_token in ref[2:].split("/"):
            token = raw_token.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or token not in current:
                raise ValidationError(f"Swagger/OpenAPI содержит битую ссылку $ref: {ref}")
            current = current[token]
        return current

    @classmethod
    def _resolve_openapi_ref(cls, document: dict, value: object, depth: int = 0) -> object:
        if depth > 20:
            raise ValidationError("Swagger/OpenAPI содержит слишком глубокую цепочку $ref")
        if isinstance(value, dict) and "$ref" in value:
            ref = value.get("$ref")
            if not isinstance(ref, str):
                raise ValidationError("Некорректный $ref в Swagger/OpenAPI документе")
            resolved = cls._resolve_json_pointer(document, ref)
            if isinstance(resolved, dict):
                merged = dict(resolved)
                merged.update({key: item for key, item in value.items() if key != "$ref"})
                return cls._resolve_openapi_ref(document, merged, depth + 1)
            return cls._resolve_openapi_ref(document, resolved, depth + 1)
        return value

    @staticmethod
    def _normalize_openapi_path(path_value: str, prefix: str) -> str:
        combined = f"{prefix.rstrip('/')}/{path_value.lstrip('/')}" if prefix else path_value
        return AssetService._normalize_endpoint_path(combined) or "/"

    @staticmethod
    def _extract_openapi_host(document: dict) -> str | None:
        swagger_host = str(document.get("host") or "").strip()
        if swagger_host:
            return re.sub(r"^https?://", "", swagger_host, flags=re.IGNORECASE).split("/", 1)[0]
        servers = document.get("servers")
        if not isinstance(servers, list):
            return None
        for server in servers:
            if not isinstance(server, dict):
                continue
            raw_url = str(server.get("url") or "").strip()
            if not raw_url or "://" not in raw_url:
                continue
            parsed = urlsplit(raw_url)
            if parsed.netloc:
                return parsed.netloc
        return None

    @staticmethod
    def _extract_openapi_path_prefix(document: dict) -> str:
        base_path = str(document.get("basePath") or "").strip()
        if base_path:
            return base_path
        servers = document.get("servers")
        if not isinstance(servers, list):
            return ""
        for server in servers:
            if not isinstance(server, dict):
                continue
            raw_url = str(server.get("url") or "").strip()
            if not raw_url:
                continue
            parsed = urlsplit(raw_url if "://" in raw_url else f"https://placeholder.local{raw_url}")
            if parsed.path and parsed.path != "/":
                return parsed.path
        return ""

    @staticmethod
    def _serialize_openapi_example(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, str):
            text = value.strip()
            return text or None
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, indent=2)
        return str(value)

    @classmethod
    def _build_openapi_example_from_schema(cls, document: dict, schema: object, depth: int = 0) -> object:
        if schema is None or depth > 8:
            return None
        resolved = cls._resolve_openapi_ref(document, schema)
        if not isinstance(resolved, dict):
            return None
        if "example" in resolved:
            return resolved.get("example")
        if "default" in resolved:
            return resolved.get("default")
        enum_values = resolved.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return enum_values[0]
        schema_type = str(resolved.get("type") or "").lower()
        if schema_type == "object" or isinstance(resolved.get("properties"), dict):
            properties = resolved.get("properties") if isinstance(resolved.get("properties"), dict) else {}
            example: dict = {}
            for prop_name, prop_schema in properties.items():
                example[prop_name] = cls._build_openapi_example_from_schema(document, prop_schema, depth + 1)
            return example
        if schema_type == "array":
            item_example = cls._build_openapi_example_from_schema(document, resolved.get("items"), depth + 1)
            return [item_example] if item_example is not None else []
        if schema_type in {"integer", "number"}:
            return 0
        if schema_type == "boolean":
            return False
        if schema_type == "file":
            return "<binary>"
        if schema_type == "string" or not schema_type:
            fmt = str(resolved.get("format") or "").lower()
            if fmt == "date-time":
                return "2024-01-01T00:00:00Z"
            if fmt == "date":
                return "2024-01-01"
            if fmt == "uuid":
                return "00000000-0000-0000-0000-000000000000"
            if fmt == "email":
                return "user@example.com"
            return "string"
        return None

    @classmethod
    def _extract_openapi_query_params(cls, document: dict, path_item: dict, operation: dict) -> list[dict]:
        collected: list[dict] = []
        seen: set[str] = set()
        for source in (path_item.get("parameters"), operation.get("parameters")):
            if not isinstance(source, list):
                continue
            for item in source:
                resolved = cls._resolve_openapi_ref(document, item)
                if not isinstance(resolved, dict) or str(resolved.get("in") or "").lower() != "query":
                    continue
                name = str(resolved.get("name") or "").strip()
                if not name or name in seen:
                    continue
                seen.add(name)
                example_value: object | None = None
                if "example" in resolved:
                    example_value = resolved.get("example")
                elif "default" in resolved:
                    example_value = resolved.get("default")
                elif isinstance(resolved.get("enum"), list) and resolved["enum"]:
                    example_value = resolved["enum"][0]
                else:
                    schema_for_value = resolved.get("schema") if isinstance(resolved.get("schema"), dict) else resolved
                    built = cls._build_openapi_example_from_schema(document, schema_for_value)
                    if built is not None and not isinstance(built, (dict, list)):
                        example_value = built
                collected.append(
                    {
                        "name": name,
                        "value": cls._serialize_openapi_example(example_value),
                        "required": bool(resolved.get("required")),
                        "description": str(resolved.get("description") or "").strip() or None,
                    }
                )
        return collected

    @classmethod
    def _collect_openapi_form_params(cls, document: dict, path_item: dict, operation: dict) -> list[dict]:
        body_param: dict | None = None
        form_params: list[dict] = []
        for source in (path_item.get("parameters"), operation.get("parameters")):
            if not isinstance(source, list):
                continue
            for item in source:
                resolved = cls._resolve_openapi_ref(document, item)
                if not isinstance(resolved, dict):
                    continue
                in_value = str(resolved.get("in") or "").lower()
                if in_value == "body" and body_param is None:
                    body_param = resolved
                elif in_value == "formdata":
                    form_params.append(resolved)
        return [{"body": body_param, "form": form_params}]

    @classmethod
    def _extract_openapi_request_details(
        cls, document: dict, path_item: dict, operation: dict
    ) -> tuple[str | None, str | None]:
        request_body = operation.get("requestBody")
        if request_body:
            resolved = cls._resolve_openapi_ref(document, request_body)
            if isinstance(resolved, dict):
                content = resolved.get("content")
                if isinstance(content, dict) and content:
                    for content_type, content_schema in content.items():
                        normalized_type = str(content_type or "").strip() or None
                        if not isinstance(content_schema, dict):
                            return normalized_type, None
                        if "example" in content_schema:
                            return normalized_type, cls._serialize_openapi_example(content_schema.get("example"))
                        examples = content_schema.get("examples")
                        if isinstance(examples, dict):
                            for example in examples.values():
                                if isinstance(example, dict) and "value" in example:
                                    return normalized_type, cls._serialize_openapi_example(example.get("value"))
                        schema = content_schema.get("schema")
                        if schema is not None:
                            built = cls._build_openapi_example_from_schema(document, schema)
                            if built is not None:
                                return normalized_type, cls._serialize_openapi_example(built)
                        return normalized_type, None
        swagger_consumes = operation.get("consumes") if isinstance(operation.get("consumes"), list) else document.get("consumes")
        consumes_list = swagger_consumes if isinstance(swagger_consumes, list) else []
        preferred_type = next(
            (str(item).strip() for item in consumes_list if isinstance(item, str) and str(item).strip()),
            None,
        )
        collected = cls._collect_openapi_form_params(document, path_item, operation)
        body_param = collected[0]["body"] if collected else None
        form_params = collected[0]["form"] if collected else []
        if body_param:
            content_type = preferred_type or "application/json"
            if "example" in body_param:
                return content_type, cls._serialize_openapi_example(body_param.get("example"))
            built = cls._build_openapi_example_from_schema(document, body_param.get("schema"))
            if built is None:
                return content_type, None
            return content_type, cls._serialize_openapi_example(built)
        if form_params:
            content_type = preferred_type or "application/x-www-form-urlencoded"
            pairs: list[tuple[str, str]] = []
            for param in form_params:
                name = str(param.get("name") or "").strip()
                if not name:
                    continue
                schema_for_value = param.get("schema") if isinstance(param.get("schema"), dict) else param
                built = cls._build_openapi_example_from_schema(document, schema_for_value)
                value_text = cls._serialize_openapi_example(built) or ""
                pairs.append((name, value_text))
            if not pairs:
                return content_type, None
            if content_type.startswith("multipart"):
                body_text = "\n".join(f"{name}={value}" for name, value in pairs)
            else:
                body_text = "&".join(f"{name}={value}" for name, value in pairs)
            return content_type, body_text or None
        return None, None

    async def import_openapi(self, project_id: int, host_id: int, payload: bytes, actor_id: int) -> OpenApiImportResult:
        host = await self.db.scalar(select(Host).where(and_(Host.id == host_id, Host.project_id == project_id)))
        if not host:
            raise NotFoundError("Хост не найден")

        self._validate_openapi_payload(payload)
        raw_text = self._decode_text_payload(payload)
        document = self._load_json_or_yaml_document(raw_text)
        paths = document.get("paths")
        if not isinstance(paths, dict) or not paths:
            raise ValidationError("В Swagger/OpenAPI документе отсутствует объект paths")
        if len(paths) > MAX_OPENAPI_PATHS:
            raise ValidationError("Swagger/OpenAPI документ содержит слишком много paths для импорта")

        spec_host = self._extract_openapi_host(document)
        result = OpenApiImportResult(
            host_id=host.id,
            spec_host=spec_host,
            endpoints_created=0,
            endpoints_skipped=0,
            errors=[],
        )
        current_host_targets = {value.lower() for value in (host.hostname, host.ip_address) if value}
        if spec_host and current_host_targets and spec_host.lower() not in current_host_targets:
            result.errors.append(
                f"В спецификации указан host '{spec_host}', но импорт выполнен в текущий хост '{host.hostname or host.ip_address}'."
            )

        supported_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        path_prefix = self._extract_openapi_path_prefix(document)

        try:
            for path_value, raw_path_item in paths.items():
                if not isinstance(path_value, str) or not path_value.strip():
                    continue
                path_item = self._resolve_openapi_ref(document, raw_path_item)
                if not isinstance(path_item, dict):
                    result.errors.append(f"Раздел paths['{path_value}'] имеет некорректную структуру и был пропущен.")
                    continue
                for raw_method_name, raw_operation in path_item.items():
                    if not isinstance(raw_method_name, str):
                        continue
                    method_name = raw_method_name.lower()
                    if method_name in {"parameters"} or method_name.startswith("x-"):
                        continue
                    if method_name not in supported_methods:
                        result.errors.append(f"Метод '{raw_method_name}' для '{path_value}' не поддерживается и был пропущен.")
                        continue
                    operation = self._resolve_openapi_ref(document, raw_operation)
                    if not isinstance(operation, dict):
                        result.errors.append(f"Операция '{raw_method_name}' для '{path_value}' имеет некорректную структуру.")
                        continue
                    if bool(operation.get("deprecated")):
                        result.errors.append(
                            f"Операция '{raw_method_name.upper()} {path_value}' помечена как deprecated и была пропущена."
                        )
                        continue
                    request_content_type, request_body = self._extract_openapi_request_details(
                        document, path_item, operation
                    )
                    endpoint_payload = {
                        "path": self._normalize_openapi_path(path_value, path_prefix),
                        "method": method_name.upper(),
                        "description": "\n\n".join(
                            part for part in [str(operation.get("summary") or "").strip(), str(operation.get("description") or "").strip()] if part
                        )
                        or None,
                        "query_params": self._extract_openapi_query_params(document, path_item, operation),
                        "request_body": request_body,
                        "request_content_type": request_content_type,
                        "request_headers": [],
                    }
                    endpoint = await self.db.scalar(
                        select(Endpoint).where(
                            and_(
                                Endpoint.host_id == host.id,
                                Endpoint.path == endpoint_payload["path"],
                                Endpoint.method == endpoint_payload["method"],
                            )
                        )
                    )
                    if endpoint is None:
                        self.db.add(
                            Endpoint(
                                host_id=host.id,
                                path=endpoint_payload["path"],
                                method=endpoint_payload["method"],
                                description=endpoint_payload["description"],
                                query_params=endpoint_payload["query_params"],
                                request_body=endpoint_payload["request_body"],
                                request_content_type=endpoint_payload["request_content_type"],
                                request_headers=[],
                            )
                        )
                        result.endpoints_created += 1
                    else:
                        self._merge_endpoint_fields(endpoint, endpoint_payload)
                        result.endpoints_skipped += 1

            if result.endpoints_created == 0 and result.endpoints_skipped == 0:
                raise ValidationError("В Swagger/OpenAPI документе не найдено методов для импорта")

            await self.db.commit()
        except Exception:
            await self.db.rollback()
            raise

        await AuditService(self.db).log(
            "CREATE",
            user_id=actor_id,
            entity_type="openapi_import",
            details=result.model_dump(mode="json"),
        )
        await ws_manager.broadcast(
            project_id,
            {"event": "updated", "entity": "endpoint", "project_id": str(project_id), "data": {"host_id": str(host_id), "imported": True}},
        )
        return result

    async def export_openapi(self, project_id: int, host_id: int) -> dict:
        """Собирает OpenAPI 3.0 документ из эндпоинтов хоста."""
        host = await self.db.scalar(select(Host).where(and_(Host.id == host_id, Host.project_id == project_id)))
        if not host:
            raise NotFoundError("Хост не найден")
        endpoints_result = await self.db.scalars(
            select(Endpoint).where(Endpoint.host_id == host.id).order_by(Endpoint.path, Endpoint.method)
        )
        endpoints = endpoints_result.all()
        title = host.hostname or host.ip_address or "API"
        server_url = None
        if host.hostname:
            server_url = f"https://{host.hostname}"
        elif host.ip_address:
            server_url = f"http://{host.ip_address}"
        document: dict = {
            "openapi": "3.0.0",
            "info": {"title": title, "version": "1.0.0"},
            "paths": {},
        }
        if server_url:
            document["servers"] = [{"url": server_url}]
        for endpoint in endpoints:
            path_value = endpoint.path or "/"
            method_value = (endpoint.method.value if endpoint.method else "GET").lower()
            path_item = document["paths"].setdefault(path_value, {})
            operation: dict = {}
            description = (endpoint.description or "").strip()
            if description:
                first_line, _, rest = description.partition("\n\n")
                operation["summary"] = first_line.strip()
                if rest.strip():
                    operation["description"] = rest.strip()
            parameters: list[dict] = []
            for raw_param in endpoint.query_params or []:
                if not isinstance(raw_param, dict):
                    continue
                name = str(raw_param.get("name") or "").strip()
                if not name:
                    continue
                parameter: dict = {
                    "name": name,
                    "in": "query",
                    "required": bool(raw_param.get("required")),
                    "schema": {"type": "string"},
                }
                description_value = str(raw_param.get("description") or "").strip()
                if description_value:
                    parameter["description"] = description_value
                example_value = raw_param.get("value")
                if example_value not in (None, ""):
                    parameter["example"] = example_value
                parameters.append(parameter)
            for raw_header in endpoint.request_headers or []:
                if not isinstance(raw_header, dict):
                    continue
                name = str(raw_header.get("name") or "").strip()
                if not name:
                    continue
                parameter = {
                    "name": name,
                    "in": "header",
                    "required": False,
                    "schema": {"type": "string"},
                }
                example_value = raw_header.get("value")
                if example_value not in (None, ""):
                    parameter["example"] = example_value
                parameters.append(parameter)
            if parameters:
                operation["parameters"] = parameters
            request_body_text = (endpoint.request_body or "").strip()
            if request_body_text:
                content_type = (endpoint.request_content_type or "application/json").strip() or "application/json"
                example_payload: object = request_body_text
                if content_type.endswith("json") or "json" in content_type.lower():
                    try:
                        example_payload = json.loads(request_body_text)
                    except (ValueError, TypeError):
                        example_payload = request_body_text
                operation["requestBody"] = {
                    "required": True,
                    "content": {content_type: {"example": example_payload}},
                }
            operation["responses"] = {"200": {"description": "OK"}}
            path_item[method_value] = operation
        return document

    async def import_json(self, project_id: int, payload: bytes, actor_id: int) -> ImportResult:
        """Импортирует данные атомарно: при ошибке откатывает всё."""
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ValidationError("Невалидный JSON-файл") from exc
        try:
            import_payload = PcfImportPayload.model_validate(parsed)
        except Exception as exc:
            raise ValidationError(f"JSON импорта не соответствует схеме PCF: {exc}") from exc

        result = ImportResult(hosts_created=0, ports_created=0, services_created=0, endpoints_created=0, errors=[])
        try:
            for host_data in import_payload.hosts:
                host = await self._find_matching_host(project_id, host_data)
                if host is None:
                    host = Host(
                        project_id=project_id,
                        ip_address=host_data.ip_address,
                        hostname=host_data.hostname,
                        status=host_data.status,
                        notes=host_data.notes,
                    )
                    self.db.add(host)
                    await self.db.flush()
                    result.hosts_created += 1
                else:
                    self._merge_host_fields(host, host_data)

                host_ips = list(
                    (
                        await self.db.scalars(
                            select(HostIpAddress).where(HostIpAddress.host_id == host.id)
                        )
                    ).all()
                )
                primary_ip = next(
                    (ip for ip in host_ips if ip.is_primary), host_ips[0] if host_ips else None
                )
                if primary_ip is None:
                    raise ValidationError(
                        "Невозможно импортировать порты: у хоста нет IP-адресов"
                    )

                for port_data in host_data.ports:
                    port = await self.db.scalar(
                        select(Port).where(
                            and_(
                                Port.ip_address_id == primary_ip.id,
                                Port.port_number == port_data.port_number,
                                Port.protocol == port_data.protocol,
                            )
                        )
                    )
                    if port is None:
                        port = Port(
                            host_id=host.id,
                            ip_address_id=primary_ip.id,
                            port_number=port_data.port_number,
                            protocol=port_data.protocol,
                            state=port_data.state,
                        )
                        self.db.add(port)
                        await self.db.flush()
                        result.ports_created += 1

                    for service_data in port_data.services:
                        service = await self.db.scalar(
                            select(Service).where(
                                and_(
                                    Service.port_id == port.id,
                                    Service.name == service_data.name,
                                )
                            )
                        )
                        if service is None:
                            self.db.add(
                                Service(
                                    port_id=port.id,
                                    name=service_data.name,
                                    version=service_data.version,
                                    banner=service_data.banner,
                                )
                            )
                            result.services_created += 1
                        else:
                            self._merge_service_fields(service, service_data)

                for endpoint_data in host_data.endpoints:
                    endpoint_payload = {
                        "path": endpoint_data.path,
                        "method": endpoint_data.method,
                        "description": endpoint_data.description,
                        "request_raw": endpoint_data.request_raw,
                        "query_params": [item.model_dump() for item in endpoint_data.query_params],
                        "request_body": endpoint_data.request_body,
                        "request_content_type": endpoint_data.request_content_type,
                        "request_headers": [item.model_dump() for item in endpoint_data.request_headers],
                    }
                    endpoint_payload = AssetService._apply_raw_request_payload(endpoint_payload)
                    endpoint_payload = AssetService._apply_structured_request_payload(endpoint_payload)
                    if not endpoint_payload.get("path"):
                        raise ValidationError("Каждый endpoint должен содержать path или request_raw")
                    if endpoint_payload.get("request_headers") is None:
                        endpoint_payload["request_headers"] = []
                    endpoint = await self.db.scalar(
                        select(Endpoint).where(
                            and_(
                                Endpoint.host_id == host.id,
                                Endpoint.path == endpoint_payload["path"],
                                Endpoint.method == endpoint_payload.get("method"),
                            )
                        )
                    )
                    if endpoint is None:
                        self.db.add(
                            Endpoint(
                                host_id=host.id,
                                path=endpoint_payload["path"],
                                method=endpoint_payload.get("method"),
                                description=endpoint_payload.get("description"),
                                query_params=endpoint_payload.get("query_params") or [],
                                request_body=endpoint_payload.get("request_body"),
                                request_content_type=endpoint_payload.get("request_content_type"),
                                request_headers=endpoint_payload.get("request_headers") or [],
                            )
                        )
                        result.endpoints_created += 1
                    else:
                        self._merge_endpoint_fields(endpoint, endpoint_payload)

            await self.db.commit()
        except Exception:
            await self.db.rollback()
            raise

        await AuditService(self.db).log("CREATE", user_id=actor_id, entity_type="import", details=result.model_dump())
        await ws_manager.broadcast(project_id, {"event": "updated", "entity": "host", "project_id": str(project_id), "data": {"imported": True}})
        return result


class ReportService:
    """Сервис генерации Word-отчётов СЗИ и ПП по предзагруженным шаблонам."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self.storage = MinioStorage()

    async def _collect_project_data(self, project_id: int) -> dict:
        project = await self.db.scalar(select(Project).where(Project.id == project_id))
        if not project:
            raise NotFoundError("Проект не найден")
        members = (
            await self.db.execute(
                select(User.username)
                .join(ProjectMember, ProjectMember.user_id == User.id)
                .where(ProjectMember.project_id == project_id)
            )
        ).all()
        vulnerabilities = (await self.db.scalars(select(Vulnerability).where(Vulnerability.project_id == project_id))).all()
        hosts = (await self.db.scalars(select(Host).where(Host.project_id == project_id))).all()
        ports = (
            await self.db.scalars(select(Port).join(Host, Port.host_id == Host.id).where(Host.project_id == project_id))
        ).all()
        vulnerability_ids = [vulnerability.id for vulnerability in vulnerabilities]
        host_ids = [host.id for host in hosts]
        vulnerability_assets = []
        files = []
        if vulnerability_ids:
            vulnerability_assets = list(
                (
                    await self.db.scalars(
                        select(VulnerabilityAsset).where(VulnerabilityAsset.vulnerability_id.in_(vulnerability_ids))
                    )
                ).all()
            )
            files = list((await self.db.scalars(select(File).where(File.vulnerability_id.in_(vulnerability_ids)))).all())
        return {
            "project": project,
            "members": [m[0] for m in members],
            "vulnerabilities": list(vulnerabilities),
            "hosts": list(hosts),
            "ports": list(ports),
            "host_ids": host_ids,
            "vulnerability_assets": vulnerability_assets,
            "files": files,
        }

    @staticmethod
    def _build_report_indexes(data: dict) -> dict:
        hosts: list[Host] = data["hosts"]
        ports: list[Port] = data["ports"]
        vulnerability_assets: list[VulnerabilityAsset] = data["vulnerability_assets"]
        files: list[File] = data["files"]
        host_by_id = {host.id: host for host in hosts}
        ports_by_host_id: dict[int, list[Port]] = {}
        for port in ports:
            ports_by_host_id.setdefault(port.host_id, []).append(port)
        assets_by_vuln_id: dict[int, list[VulnerabilityAsset]] = {}
        for asset in vulnerability_assets:
            assets_by_vuln_id.setdefault(asset.vulnerability_id, []).append(asset)
        files_by_vuln_id: dict[int, list[File]] = {}
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

    @staticmethod
    def _resolve_step_files(step: dict, files_by_id: dict[int, File]) -> list[File]:
        resolved: list[File] = []
        for raw_file_id in step.get("image_file_ids", []):
            try:
                file_id = int(raw_file_id)
            except (TypeError, ValueError):
                continue
            file_meta = files_by_id.get(file_id)
            if file_meta:
                resolved.append(file_meta)
        return resolved

    @staticmethod
    def _is_image_file(file_meta: File) -> bool:
        return file_meta.content_type.startswith("image/")

    @staticmethod
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

    async def _download_report_images(self, files: list[File]) -> dict[int, bytes]:
        image_bytes: dict[int, bytes] = {}
        for file_meta in files:
            if not self._is_image_file(file_meta):
                continue
            try:
                raw_bytes = await asyncio.to_thread(self.storage.download_bytes, file_meta.minio_key)
            except Exception:
                continue
            normalized_bytes = await asyncio.to_thread(self._normalize_report_image_bytes, raw_bytes)
            if normalized_bytes:
                image_bytes[file_meta.id] = normalized_bytes
        return image_bytes

    async def generate(self, project_id: int, kind: Literal["szi", "pp"]) -> bytes:
        """Генерирует Word-отчёт указанного типа.

        ``kind`` — `szi` (отчёт на сертификацию) или `pp` (внутренняя приёмка).
        """
        if kind not in ("szi", "pp"):
            raise ValidationError("Неподдерживаемый тип отчёта")
        data = await self._collect_project_data(project_id)
        for vuln in data["vulnerabilities"]:
            VulnerabilityService._hydrate_workflow_steps(vuln)
        indexes = self._build_report_indexes(data)
        image_bytes_by_id = await self._download_report_images(data["files"])
        builder = build_szi if kind == "szi" else build_pp
        return await asyncio.to_thread(builder, data, indexes, image_bytes_by_id)
