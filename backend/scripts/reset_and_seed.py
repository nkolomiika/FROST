"""Сброс демо-данных и пересид БД (пользователей сохраняет).

Запуск из каталога backend:
    PYTHONPATH=/app python scripts/reset_and_seed.py   # Docker
    python scripts/reset_and_seed.py                   # локально, если backend в PYTHONPATH
"""
import asyncio
import base64
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from uuid import uuid4

# Позволяет выполнять файл напрямую без предварительного export PYTHONPATH=/app
_backend_root = Path(__file__).resolve().parent.parent
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from sqlalchemy import text, select

from app.config import get_settings
from app.database import Base, SessionLocal, engine
from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    NotificationType,
    PortState,
    ProjectRole,
    ProjectStatus,
    Protocol,
    Severity,
    UserRole,
    VulnerabilityStatus,
)
from app.models import (
    AgentApiToken,
    AgentApiTokenProjectGrant,
    AuditLog,
    Comment,
    CommentMention,
    Endpoint,
    File,
    Host,
    HostIpAddress,
    Notification,
    Port,
    Project,
    ProjectFolder,
    ProjectMember,
    ProjectNote,
    ProjectNoteComment,
    Service,
    User,
    Vulnerability,
    VulnerabilityAsset,
)
from app.security import hash_agent_token, hash_password
from app.services import UserService
from app.storage.minio_client import MinioStorage

DEMO_PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wn0K6sAAAAASUVORK5CYII="
)


async def ensure_schema() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


def reset_minio(minio_keys: list[str]) -> None:
    if not minio_keys:
        return
    storage = MinioStorage()
    storage.ensure_bucket()
    for object_key in minio_keys:
        try:
            storage.client.remove_object(storage.bucket, object_key)
        except Exception:
            # Объект может отсутствовать в MinIO (например, был удалён вручную).
            pass


async def create_users() -> dict[str, User]:
    settings = get_settings()
    users: dict[str, User] = {}
    async with SessionLocal() as db:
        await UserService(db).bootstrap_admin()
        admin = await db.scalar(select(User).where(User.username == settings.initial_admin_username))
        if not admin:
            raise RuntimeError("Admin user was not created")
        users["admin"] = admin

        # (username, email, аккаунтная роль, проектная роль). Проектная роль
        # глобальная: лид — обычный юзер, но с доп. возможностями в своих проектах.
        demo_users = [
            ("alice", "alice@example.com", UserRole.PENTESTER, ProjectRole.LEAD),
            ("bob", "bob@example.com", UserRole.PENTESTER, ProjectRole.LEAD),
            ("charlie", "charlie@example.com", UserRole.PENTESTER, ProjectRole.PENTESTER),
            ("diana", "diana@example.com", UserRole.PENTESTER, ProjectRole.PENTESTER),
            ("eve", "eve@example.com", UserRole.PENTESTER, ProjectRole.PENTESTER),
        ]
        for username, email, role, project_role in demo_users:
            user = await db.scalar(select(User).where(User.username == username))
            if not user:
                user = await db.scalar(select(User).where(User.email == email))
            if not user:
                user = User(
                    username=username,
                    email=email,
                    password_hash=hash_password("admin"),
                    role=role,
                    project_role=project_role,
                    is_active=True,
                )
                db.add(user)
                await db.flush()
            users[username] = user
        await db.commit()
    return users


async def clear_domain_data_preserve_users() -> list[str]:
    async with SessionLocal() as db:
        minio_keys = list((await db.scalars(select(File.minio_key).where(File.minio_key.is_not(None)))).all())
        await db.execute(
            text(
                """
                TRUNCATE TABLE
                    comment_mentions,
                    notifications,
                    comments,
                    project_note_comments,
                    project_notes,
                    vulnerability_assets,
                    files,
                    vulnerabilities,
                    services,
                    ports,
                    endpoints,
                    host_ip_addresses,
                    hosts,
                    project_members,
                    agent_api_token_project_grants,
                    agent_api_tokens,
                    projects,
                    project_folders,
                    mail_jobs,
                    audit_logs
                RESTART IDENTITY CASCADE
                """
            )
        )
        await db.commit()
    return minio_keys


async def seed_demo_data() -> None:
    users = await create_users()
    storage = MinioStorage()
    storage.ensure_bucket()
    now = datetime.now(UTC)
    today = date.today()
    severity_cycle = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    status_cycle = [
        VulnerabilityStatus.OPEN,
        VulnerabilityStatus.IN_PROGRESS,
        VulnerabilityStatus.FIXED,
        VulnerabilityStatus.ACCEPTED_RISK,
    ]
    project_statuses = [ProjectStatus.ACTIVE, ProjectStatus.ACTIVE, ProjectStatus.COMPLETED, ProjectStatus.ARCHIVED]
    folder_specs = [
        ("External Audits", None),
        ("Internal", None),
        ("Red Team", None),
        ("Phase 1", "Red Team"),
        ("Phase 2", "Red Team"),
        ("Mobile", "External Audits"),
        ("API", "External Audits"),
        ("Infrastructure", "Internal"),
    ]

    async with SessionLocal() as db:
        admin = await db.scalar(select(User).where(User.username == "admin"))
        if not admin:
            raise RuntimeError("Admin user is missing")

        folders_by_path: dict[str, ProjectFolder] = {}
        for folder_name, parent_path in folder_specs:
            path = f"{parent_path}/{folder_name}" if parent_path else folder_name
            parent = folders_by_path.get(parent_path) if parent_path else None
            folder = ProjectFolder(
                name=folder_name,
                path=path,
                parent_id=parent.id if parent else None,
                created_by=admin.id,
            )
            db.add(folder)
            await db.flush()
            folders_by_path[path] = folder

        project_specs = [
            ("Acme External API", "External Audits/API", ProjectStatus.ACTIVE, [users["alice"], users["bob"], users["diana"]]),
            ("Contoso Mobile", "External Audits/Mobile", ProjectStatus.ACTIVE, [users["alice"], users["eve"]]),
            ("Intranet Review", "Internal/Infrastructure", ProjectStatus.ACTIVE, [users["bob"], users["charlie"]]),
            ("Red Team Alpha", "Red Team/Phase 1", ProjectStatus.ACTIVE, [users["alice"], users["charlie"], users["diana"]]),
            ("Red Team Bravo", "Red Team/Phase 2", ProjectStatus.COMPLETED, [users["bob"], users["eve"]]),
            ("Partner Portal", "", ProjectStatus.ACTIVE, [users["alice"], users["bob"]]),
            ("Legacy ERP", "", ProjectStatus.ARCHIVED, [users["charlie"], users["diana"]]),
            ("Corporate SSO", "Internal", ProjectStatus.COMPLETED, [users["alice"], users["eve"]]),
        ]

        audit_rows: list[dict] = []
        file_counter = 0

        for project_index, (project_name, folder_path, project_status, members) in enumerate(project_specs, start=1):
            start_date = today - timedelta(days=14 + project_index)
            end_date = today + timedelta(days=14 - project_index if project_status == ProjectStatus.ACTIVE else -project_index)
            # Окно, в котором раскидываем created_at активов и находок, чтобы виджеты-
            # графики росли: от старта проекта до «сегодня» (но не позже конца проекта).
            p_start_dt = datetime.combine(start_date, datetime.min.time(), tzinfo=UTC)
            p_end_dt = datetime.combine(end_date, datetime.min.time(), tzinfo=UTC)
            data_hi = min(now, p_end_dt)
            if data_hi <= p_start_dt:
                data_hi = p_start_dt + timedelta(days=1)

            def added_at(frac: float, _lo=p_start_dt, _hi=data_hi) -> datetime:
                """created_at на доле `frac` окна проекта [start … min(now, end)]."""
                return _lo + (_hi - _lo) * max(0.0, min(1.0, frac))

            project = Project(
                name=project_name,
                folder=folder_path,
                description=f"Тестовый проект '{project_name}' с набором активов, уязвимостей и совместной работы.",
                start_date=start_date,
                end_date=end_date,
                status=project_statuses[(project_index - 1) % len(project_statuses)] if project_status is None else project_status,
                created_by=admin.id,
                # Проект «заведён» в день своего старта — разносит точки на графиках
                # количества проектов на главной странице.
                created_at=p_start_dt,
                updated_at=p_start_dt,
            )
            db.add(project)
            await db.flush()

            db.add(ProjectMember(project_id=project.id, user_id=admin.id))
            for member in members:
                db.add(ProjectMember(project_id=project.id, user_id=member.id))
                # Повод №2: их в проект добавил админ — ровно то же уведомление,
                # что создаёт add_member. Себе админ его не шлёт.
                db.add(
                    Notification(
                        user_id=member.id,
                        type=NotificationType.PROJECT_MEMBER_ADDED,
                        project_id=project.id,
                        actor_id=admin.id,
                        is_read=False,
                    )
                )
            await db.flush()

            audit_rows.append(
                {
                    "user_id": admin.id,
                    "username": admin.username,
                    "action": "CREATE",
                    "entity_type": "project",
                    "entity_id": project.id,
                    "details": {"project": project.name, "folder": folder_path or "root"},
                    "ip_address": "127.0.0.1",
                    "created_at": now - timedelta(days=project_index),
                }
            )

            # === Заметки проекта (вложенное дерево из 3 уровней) ===
            note_root = ProjectNote(
                project_id=project.id,
                title=f"Главная страница «{project_name}»",
                content=(
                    f"# Обзор проекта «{project_name}»\n\n"
                    "Это корневая заметка проекта со ссылками на ключевые разделы:\n\n"
                    "- Цели и скоуп\n"
                    "- План работ\n"
                    "- Контактные лица заказчика\n\n"
                    f"Команда: @{members[0].username if members else admin.username}, "
                    f"@{members[-1].username if len(members) > 1 else admin.username}.\n"
                ),
                sort_order=0,
                created_by=admin.id,
                updated_by=admin.id,
            )
            db.add(note_root)
            await db.flush()

            note_methodology = ProjectNote(
                project_id=project.id,
                parent_id=note_root.id,
                title="Методология",
                content=(
                    "## Подход\n\n"
                    "1. Сбор информации (OSINT, поддомены, сертификаты)\n"
                    "2. Активная разведка (Nmap, DirBuster)\n"
                    "3. Анализ уязвимостей (SAST/DAST)\n"
                    "4. Эксплуатация (ручная и автоматизированная)\n"
                    "5. Подготовка отчёта\n"
                ),
                sort_order=1,
                created_by=admin.id,
                updated_by=members[0].id if members else admin.id,
            )
            db.add(note_methodology)
            await db.flush()

            note_findings = ProjectNote(
                project_id=project.id,
                parent_id=note_root.id,
                title="Ключевые находки",
                content=(
                    "## Top-3\n\n"
                    "- **SSRF** в loadbalancer (см. уязвимость #1 в overview)\n"
                    "- **Слабые пароли** на staging\n"
                    "- **Утечка JWT-секрета** через debug endpoint\n\n"
                    f"Подробности у @{members[0].username if members else admin.username}.\n"
                ),
                sort_order=2,
                created_by=members[0].id if members else admin.id,
                updated_by=members[0].id if members else admin.id,
            )
            db.add(note_findings)
            await db.flush()

            note_subpage = ProjectNote(
                project_id=project.id,
                parent_id=note_methodology.id,
                title="Чек-лист инструментов",
                content=(
                    "- nmap 7.94\n- gobuster 3.6\n- sqlmap 1.7\n- Burp Suite Pro\n- ZAP\n"
                ),
                sort_order=0,
                created_by=members[0].id if members else admin.id,
                updated_by=members[0].id if members else admin.id,
            )
            db.add(note_subpage)
            await db.flush()

            # === Комментарии к заметкам, с упоминанием → уведомление ===
            commenter_note = members[1] if len(members) > 1 else admin
            mentioned_note = members[0] if members else admin
            note_comment = ProjectNoteComment(
                project_id=project.id,
                note_id=note_findings.id,
                user_id=commenter_note.id,
                content=f"@{mentioned_note.username} обрати внимание на SSRF — нужна повторная проверка после фикса.",
            )
            db.add(note_comment)
            await db.flush()
            db.add(
                Notification(
                    user_id=mentioned_note.id,
                    type=NotificationType.MENTION,
                    note_comment_id=note_comment.id,
                    is_read=False,
                )
            )
            note_comment_extra = ProjectNoteComment(
                project_id=project.id,
                note_id=note_root.id,
                user_id=admin.id,
                content="Скоуп подтверждён. Можно стартовать активную фазу.",
            )
            db.add(note_comment_extra)

            for host_index in range(1, 4):
                primary_ip = f"10.{project_index}.{host_index}.10"
                # 3 хоста → 25% / 50% / 75% окна проекта: график хостов растёт ступеньками.
                host_time = added_at(host_index / 4.0)
                host = Host(
                    project_id=project.id,
                    ip_address=primary_ip,
                    hostname=f"{project_name.lower().replace(' ', '-')}-host-{host_index}.demo.local",
                    status=HostStatus.UP if host_index != 2 else HostStatus.UNKNOWN,
                    notes=f"Описание тестового хоста {host_index} для проекта {project_name}.",
                    created_at=host_time,
                    updated_at=host_time,
                )
                db.add(host)
                await db.flush()

                # Сид пишет audit и для инвентаря — иначе созданные хосты/IP/порты
                # не попадут в ленту активности проекта.
                audit_rows.append(
                    {
                        "user_id": admin.id,
                        "username": admin.username,
                        "action": "CREATE",
                        "entity_type": "host",
                        "entity_id": host.id,
                        "details": {"project_id": str(project.id), "hostname": host.hostname, "ip_address": primary_ip},
                        "ip_address": "127.0.0.1",
                        "created_at": now - timedelta(days=project_index, hours=host_index),
                    }
                )

                # Несколько IP у хоста (внутренний/внешний/management) — проверка таблицы host_ip_addresses.
                host_ip_rows: dict[str, HostIpAddress] = {}
                for ip_suffix, label, is_primary in [
                    (primary_ip, "external", True),
                    (f"10.{project_index}.{host_index}.20", "internal", False),
                    (f"172.16.{project_index}.{host_index}", "mgmt", False),
                ]:
                    ip_row = HostIpAddress(
                        host_id=host.id,
                        ip_address=ip_suffix,
                        label=label,
                        is_primary=is_primary,
                        created_at=host_time,
                        updated_at=host_time,
                    )
                    db.add(ip_row)
                    host_ip_rows[label] = ip_row
                await db.flush()
                for label, ip_row in host_ip_rows.items():
                    audit_rows.append(
                        {
                            "user_id": admin.id,
                            "username": admin.username,
                            "action": "CREATE",
                            "entity_type": "host_ip_address",
                            "entity_id": ip_row.id,
                            "details": {"project_id": str(project.id), "ip_address": ip_row.ip_address, "label": label},
                            "ip_address": "127.0.0.1",
                            "created_at": now - timedelta(days=project_index, hours=host_index),
                        }
                    )

                ports_for_host: list[Port] = []
                for port_number, protocol, state, service_name, version, ip_label in [
                    (22, Protocol.TCP, PortState.OPEN, "ssh", "OpenSSH_9.6", "mgmt"),
                    (80, Protocol.TCP, PortState.OPEN, "http", "nginx/1.25", "external"),
                    (443, Protocol.TCP, PortState.OPEN, "https", "nginx/1.25", "external"),
                    (8080, Protocol.TCP, PortState.FILTERED if host_index == 3 else PortState.OPEN, "tomcat", "10.1", "internal"),
                ]:
                    target_ip = host_ip_rows[ip_label]
                    port = Port(
                        host_id=host.id,
                        ip_address_id=target_ip.id,
                        port_number=port_number,
                        protocol=protocol,
                        state=state,
                        created_at=host_time,
                        updated_at=host_time,
                    )
                    db.add(port)
                    await db.flush()
                    ports_for_host.append(port)
                    audit_rows.append(
                        {
                            "user_id": admin.id,
                            "username": admin.username,
                            "action": "CREATE",
                            "entity_type": "port",
                            "entity_id": port.id,
                            "details": {
                                "project_id": str(project.id),
                                "port": f"{port_number}/{protocol.value}",
                                "service": service_name,
                            },
                            "ip_address": "127.0.0.1",
                            "created_at": now - timedelta(days=project_index, hours=host_index),
                        }
                    )
                    db.add(
                        Service(
                            port_id=port.id,
                            name=service_name,
                            version=version,
                            banner=f"{service_name} banner for {project_name}",
                            created_at=host_time,
                            updated_at=host_time,
                        )
                    )

                endpoints: list[Endpoint] = []
                for method, path_suffix, description in [
                    (HttpMethod.GET, "/api/health", "Проверка состояния сервиса"),
                    (HttpMethod.POST, "/api/login", "Точка входа пользователей"),
                    (HttpMethod.GET, "/api/users", "Получение списка пользователей"),
                ]:
                    endpoint = Endpoint(
                        host_id=host.id,
                        path=path_suffix,
                        method=method,
                        description=f"{description} ({project_name})",
                        created_at=host_time,
                        updated_at=host_time,
                    )
                    db.add(endpoint)
                    await db.flush()
                    endpoints.append(endpoint)
                    audit_rows.append(
                        {
                            "user_id": admin.id,
                            "username": admin.username,
                            "action": "CREATE",
                            "entity_type": "endpoint",
                            "entity_id": endpoint.id,
                            "details": {
                                "project_id": str(project.id),
                                "endpoint": f"{method.value} {path_suffix}",
                            },
                            "ip_address": "127.0.0.1",
                            "created_at": now - timedelta(days=project_index, hours=host_index),
                        }
                    )

                for vuln_index in range(1, 3):
                    # 6 находок на проект, разнесены по окну (0.11 … 0.89) — график
                    # уязвимостей и «моих находок» на overview растёт плавной лесенкой.
                    vuln_time = added_at((host_index - 1 + vuln_index / 3.0) / 3.0)
                    vuln = Vulnerability(
                        project_id=project.id,
                        title=f"{project_name} / Host {host_index} / Finding {vuln_index}",
                        description="Тестовая уязвимость для проверки host-centric сценариев.",
                        severity=severity_cycle[(project_index + host_index + vuln_index) % len(severity_cycle)],
                        cvss_version=CvssVersion.V40,
                        cvss_score=8.7 if vuln_index % 2 else 9.3,
                        cvss_vector=(
                            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                            if vuln_index % 2
                            else "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L"
                        ),
                        cwe_id="CWE-79" if vuln_index % 2 else "CWE-89",
                        status=status_cycle[(project_index + vuln_index) % len(status_cycle)],
                        # Каждый шаг — отдельная запись: в карточке у него своё поле,
                        # а номер рисует интерфейс, поэтому в тексте нумерации нет.
                        workflow_steps=[
                            {"id": str(uuid4()), "description": text, "image_file_ids": [], "endpoint_id": None, "endpoint_request_raw": None}
                            for text in (
                                "Выполнить запрос",
                                "Получить некорректный ответ",
                                "Зафиксировать результат",
                            )
                        ],
                        steps_to_reproduce="Выполнить запрос\nПолучить некорректный ответ\nЗафиксировать результат",
                        impact="Компрометация конфиденциальности и/или целостности данных.",
                        recommendations="Ограничить доступ, валидировать входные данные и усилить аутентификацию.",
                        created_by=members[0].id if members else admin.id,
                        created_at=vuln_time,
                        updated_at=vuln_time,
                    )
                    db.add(vuln)
                    await db.flush()

                    db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.HOST, asset_id=host.id))
                    if ports_for_host:
                        db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.PORT, asset_id=ports_for_host[0].id))
                    if endpoints:
                        db.add(VulnerabilityAsset(vulnerability_id=vuln.id, asset_type=AssetType.ENDPOINT, asset_id=endpoints[0].id))

                    file_counter += 1
                    png_bytes = DEMO_PNG_BYTES
                    png_key = storage.upload_bytes(png_bytes, "image/png", f"evidence-{project_index}-{host_index}-{vuln_index}.png")
                    db.add(
                        File(
                            vulnerability_id=vuln.id,
                            original_name=f"evidence-{project_index}-{host_index}-{vuln_index}.png",
                            content_type="image/png",
                            size_bytes=len(png_bytes),
                            minio_bucket=storage.bucket,
                            minio_key=png_key,
                            uploaded_by=members[0].id if members else admin.id,
                        )
                    )

                    report_bytes = f"Demo evidence for {project_name} host {host_index} vuln {vuln_index}".encode("utf-8")
                    report_key = storage.upload_bytes(report_bytes, "text/plain", f"notes-{project_index}-{host_index}-{vuln_index}.txt")
                    db.add(
                        File(
                            vulnerability_id=vuln.id,
                            original_name=f"notes-{project_index}-{host_index}-{vuln_index}.txt",
                            content_type="text/plain",
                            size_bytes=len(report_bytes),
                            minio_bucket=storage.bucket,
                            minio_key=report_key,
                            uploaded_by=admin.id,
                        )
                    )

                    author = members[0] if members else admin
                    mentioned = members[-1] if len(members) > 1 else admin
                    comment = Comment(
                        vulnerability_id=vuln.id,
                        user_id=author.id,
                        content=f"Проверено автором @{mentioned.username}. Нужно перепроверить доступ к {host.hostname}.",
                    )
                    db.add(comment)
                    await db.flush()
                    db.add(CommentMention(comment_id=comment.id, user_id=mentioned.id))
                    db.add(Notification(user_id=mentioned.id, type=NotificationType.MENTION, comment_id=comment.id, is_read=False))

                    audit_rows.append(
                        {
                            "user_id": author.id,
                            "username": author.username,
                            "action": "CREATE",
                            "entity_type": "vulnerability",
                            "entity_id": vuln.id,
                            "details": {"project": project.name, "host": host.hostname, "severity": vuln.severity.value},
                            "ip_address": f"10.255.{project_index}.{host_index}",
                            "created_at": now - timedelta(hours=project_index * host_index * vuln_index),
                        }
                    )

        # === API-токены агента: 2 шт. — один на все проекты, один на конкретный ===
        all_proj_token_raw = "demo-agent-token-allprojects-0001"
        all_proj_token = AgentApiToken(
            name="Demo: все проекты",
            token_hash=hash_agent_token(all_proj_token_raw),
            token_prefix=all_proj_token_raw[:8],
            scopes=["projects:read", "assets:read", "notes:read", "vulns:read"],
            all_projects=True,
            created_by=admin.id,
        )
        db.add(all_proj_token)

        first_project = await db.scalar(select(Project).order_by(Project.created_at.asc()))
        scoped_token_raw = "demo-agent-token-scoped-0002"
        scoped_token = AgentApiToken(
            name="Demo: один проект (read-only)",
            token_hash=hash_agent_token(scoped_token_raw),
            token_prefix=scoped_token_raw[:8],
            scopes=["projects:read", "vulns:read", "notes:read"],
            all_projects=False,
            created_by=admin.id,
        )
        db.add(scoped_token)
        await db.flush()
        if first_project:
            db.add(AgentApiTokenProjectGrant(token_id=scoped_token.id, project_id=first_project.id))

        for row in audit_rows:
            db.add(
                AuditLog(
                    user_id=row["user_id"],
                    action=row["action"],
                    entity_type=row["entity_type"],
                    entity_id=row["entity_id"],
                    details=row["details"],
                    ip_address=row["ip_address"],
                    created_at=row["created_at"],
                )
            )

        await db.commit()


async def main() -> None:
    await ensure_schema()
    minio_keys = await clear_domain_data_preserve_users()
    reset_minio(minio_keys)
    await seed_demo_data()
    print("Database reseed complete. Existing users were preserved; demo data for projects/assets/vulnerabilities was refreshed.")


if __name__ == "__main__":
    asyncio.run(main())
