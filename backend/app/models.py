from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.enums import (
    AssetType,
    CvssVersion,
    HostStatus,
    HttpMethod,
    NotificationType,
    OsType,
    PortState,
    ProjectRole,
    ProjectStatus,
    Protocol,
    Severity,
    UserRole,
    VulnerabilityStatus,
)


class TimestampMixin:
    """Добавляет поля created_at/updated_at."""

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class User(Base, TimestampMixin):
    """Пользователь системы."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_minio_bucket: Mapped[str | None] = mapped_column(String(63), nullable=True)
    avatar_minio_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    avatar_content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    avatar_uploaded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # TOTP-2FA (RFC 6238). Секрет хранится зашифрованным (Fernet), см. security.encrypt_secret.
    # totp_secret может быть выставлен на этапе setup, но пока totp_enabled=false код при
    # логине не спрашивается — это защищает от блокировки при незавершённой настройке.
    totp_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    totp_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.PENTESTER)
    # Проектная роль — глобальная, настраивается в /members. Лид = обычный юзер,
    # которому открыты доп. возможности в проектах, где он участник.
    project_role: Mapped[ProjectRole] = mapped_column(
        Enum(ProjectRole, name="project_role"),
        nullable=False,
        default=ProjectRole.PENTESTER,
        server_default=ProjectRole.PENTESTER.name,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Административная блокировка (мягкое удаление): «удаление» пользователя не
    # стирает строку — она бы утащила за собой его проекты/находки/заметки (FK
    # RESTRICT) — а лишь выставляет этот флаг. Заблокированный не может войти и не
    # проходит get_current_user, но всё авторство и связи остаются целыми.
    is_locked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")

    @property
    def avatar_url(self) -> str | None:
        if not self.avatar_minio_key:
            return None
        version = int(self.avatar_uploaded_at.timestamp()) if self.avatar_uploaded_at else 0
        return f"/api/v1/users/{self.id}/avatar?v={version}"


class RefreshToken(Base):
    """Хранилище активных refresh-токенов (в виде хэшей)."""

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentApiToken(Base, TimestampMixin):
    """Bearer-токен для машинного `/api/v2` доступа AI-агентов."""

    __tablename__ = "agent_api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # name — TEXT без ограничения длины: бывают токены с длинными описательными
    # именами ("Jenkins CI / nightly scan for project X / scope: vulns+notes"),
    # не хотим ловить отказ на UI.
    name: Mapped[str] = mapped_column(Text, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scopes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    all_projects: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AgentApiTokenProjectGrant(Base):
    """Разрешение agent token на конкретный проект."""

    __tablename__ = "agent_api_token_project_grants"
    __table_args__ = (UniqueConstraint("token_id", "project_id", name="uq_agent_api_token_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_id: Mapped[int] = mapped_column(Integer, ForeignKey("agent_api_tokens.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class MailJob(Base, TimestampMixin):
    """Задание на отправку письма пользователю."""

    __tablename__ = "mail_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recipient_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    template: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", server_default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Invitation(Base, TimestampMixin):
    """Приглашение нового пользователя по email.

    Пока приглашение не принято, записи в ``users`` нет — поэтому вход по будущему
    юзернейму/email до активации отдаёт обычную ошибку «неверный логин или пароль».
    При активации приглашённый сам выбирает username и пароль, и создаётся User.
    """

    __tablename__ = "invitations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole, name="user_role"), nullable=False, default=UserRole.PENTESTER)
    project_role: Mapped[ProjectRole] = mapped_column(
        Enum(ProjectRole, name="project_role"),
        nullable=False,
        default=ProjectRole.PENTESTER,
        server_default=ProjectRole.PENTESTER.name,
    )
    # SHA-256 от «сырого» токена из письма — сам токен в БД не храним (как refresh-токены).
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    # pending | accepted | revoked. Истёкшее приглашение остаётся pending — «протухло»
    # вычисляется по expires_at, чтобы админ мог переотправить его тем же действием.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", server_default="pending", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    invited_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    accepted_user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    @property
    def is_expired(self) -> bool:
        """Приглашение ещё в статусе pending, но срок жизни ссылки истёк."""
        return self.status == "pending" and self.expires_at is not None and self.expires_at <= datetime.now(UTC)


class PasswordResetToken(Base):
    """Одноразовый токен восстановления пароля («забыли пароль»).

    В БД лежит только SHA-256 от токена из письма. Токен одноразовый: после
    успешной смены пароля проставляется ``used_at`` и ссылка перестаёт работать.
    """

    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    @property
    def is_usable(self) -> bool:
        """Ссылку ещё не использовали и она не истекла."""
        return self.used_at is None and self.expires_at > datetime.now(UTC)


class AccountReactivationToken(Base):
    """Одноразовый токен возврата деактивированного пользователя.

    Админ «удаляет» пользователя = блокирует (is_locked). Возврат идёт по ссылке
    из письма: пользователь переходит по ней, аккаунт разблокируется и сразу
    выдаётся сессия. В БД, как и для сброса пароля, лежит только SHA-256 токена.
    """

    __tablename__ = "account_reactivation_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    @property
    def is_usable(self) -> bool:
        """Ссылку ещё не использовали и она не истекла."""
        return self.used_at is None and self.expires_at > datetime.now(UTC)


class Project(Base, TimestampMixin):
    """Пентест-проект."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    folder: Mapped[str] = mapped_column(String(255), nullable=False, default="", server_default="")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    timeline_frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[ProjectStatus] = mapped_column(
        Enum(ProjectStatus, name="project_status"), nullable=False, default=ProjectStatus.ACTIVE
    )
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectFolder(Base, TimestampMixin):
    """Папка проектов с поддержкой иерархии."""

    __tablename__ = "project_folders"
    __table_args__ = (
        UniqueConstraint("parent_id", "name", name="uq_project_folder_parent_name"),
        UniqueConstraint("path", name="uq_project_folder_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    parent_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_folders.id", ondelete="CASCADE"),
        nullable=True,
    )
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectMember(Base):
    """Связь участника с проектом."""

    __tablename__ = "project_members"
    __table_args__ = (UniqueConstraint("project_id", "user_id", name="uq_project_member"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class JiraInstance(Base, TimestampMixin):
    """Глобальная конфигурация Jira для backend-only интеграции."""

    __tablename__ = "jira_instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, default="default", server_default="default")
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    api_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    default_issue_type: Mapped[str] = mapped_column(String(100), nullable=False, default="Task", server_default="Task")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectJiraLink(Base, TimestampMixin):
    """Привязка проекта PCF к Jira project key."""

    __tablename__ = "project_jira_links"
    __table_args__ = (UniqueConstraint("project_id", name="uq_project_jira_link_project"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    jira_project_key: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)


class ProjectNote(Base, TimestampMixin):
    """Вложенная заметка проекта (Confluence-like)."""

    __tablename__ = "project_notes"
    __table_args__ = (UniqueConstraint("project_id", "parent_id", "title", name="uq_project_note_sibling_title"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_notes.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    updated_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    # Автор нужен в выдаче по имени: список пользователей доступен только админу,
    # поэтому имя резолвим на бэке, а не на фронте. Два FK на users → foreign_keys
    # обязателен, иначе связь неоднозначна.
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], lazy="selectin")

    @property
    def created_by_username(self) -> str | None:
        """Имя автора заметки для ProjectNoteOut."""
        return self.creator.username if self.creator else None


class ProjectNoteComment(Base, TimestampMixin):
    """Комментарий к странице заметки проекта."""

    __tablename__ = "project_note_comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    note_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("project_notes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)


class ProjectCredential(Base, TimestampMixin):
    """Учётные данные проекта — пара «username + password».

    Общее хранилище аккаунтов для команды: доступ на чтение и правку есть у всех
    участников проекта. Пароль шифруется at rest через
    :func:`app.security.encrypt_secret` — в БД лежит только шифртекст.
    """

    __tablename__ = "project_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Пароль — только шифртекст (Fernet), см. security.encrypt_secret.
    password_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # От какого хоста креды — свободная строка (IP/имя/кластер), не FK: креды
    # могут указывать на цель, которой ещё нет в списке хостов проекта.
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)

    # Имя автора отдаём вместе с кредом: /users доступен только админу, а автора
    # видят все участники проекта (тот же приём, что у заметок и находок).
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], lazy="selectin")

    @property
    def created_by_username(self) -> str | None:
        """Имя автора креда для ProjectCredentialOut."""
        return self.creator.username if self.creator else None


class Host(Base, TimestampMixin):
    """Хост инфраструктуры проекта.

    Поле ``ip_address`` сохранено для обратной совместимости и хранит «основной»
    IP-адрес (тот же, что и ``HostIpAddress.is_primary == True``). Полный список
    IP-адресов хоста ведётся в отдельной таблице :class:`HostIpAddress`.
    """

    __tablename__ = "hosts"
    __table_args__ = (
        CheckConstraint("ip_address IS NOT NULL OR hostname IS NOT NULL", name="ck_host_ip_or_hostname"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[HostStatus] = mapped_column(Enum(HostStatus, name="host_status"), nullable=False, default=HostStatus.UNKNOWN)
    os_type: Mapped[OsType] = mapped_column(
        Enum(OsType, name="host_os_type"),
        nullable=False,
        default=OsType.UNKNOWN,
        server_default=OsType.UNKNOWN.name,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 'host' — добавлен как хост (виден в списке хостов);
    # 'ip'   — служебный родитель для импорта IP: порты ссылаются на
    #          host_ip_addresses, а те на hosts, поэтому строка нужна, но в
    #          списке хостов не показывается (см. AssetService.list_hosts).
    #          Отличать по «hostname IS NULL» нельзя: ферма хостов тоже пишет
    #          NULL, когда в список хостов вставили IP-литерал.
    origin: Mapped[str] = mapped_column(
        String(16), nullable=False, default="host", server_default="host", index=True
    )

    ip_addresses: Mapped[list["HostIpAddress"]] = relationship(
        "HostIpAddress",
        back_populates="host",
        cascade="all, delete-orphan",
        order_by="HostIpAddress.created_at",
    )


class HostIpAddress(Base, TimestampMixin):
    """Один IP-адрес хоста — у одного хоста их может быть несколько."""

    __tablename__ = "host_ip_addresses"
    __table_args__ = (
        UniqueConstraint("host_id", "ip_address", name="uq_host_ip_address"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    # Имена, в которые резолвится адрес: [{"hostname", "source", "confirmed"}].
    # source: ptr — PTR-запись адреса, project — имя известного хоста проекта;
    # confirmed — прямой резолв имени вернул этот же адрес. Неподтверждённые
    # имена храним тоже: PTR контролирует владелец адреса, это подсказка.
    # NB: обычная JSON-колонка не отслеживает мутацию на месте — присваивать
    # список целиком, не .append().
    hostnames: Mapped[list | None] = mapped_column(JSON, nullable=True)
    # За адресом Cloudflare. Трёхзначно: True — виден CF (CIDR или заголовки/детект
    # пробива), False — достоверно НЕ CF (хост ответил, сигнала нет), NULL — неизвестно
    # (ещё пробится / не ответил). Пересчитывается при каждой записи, но True в NULL/False
    # без достоверного отрицательного сигнала не понижается (см. farm._ensure_ips).
    is_cloudflare: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=None)

    host: Mapped[Host] = relationship("Host", back_populates="ip_addresses")
    ports: Mapped[list["Port"]] = relationship(
        "Port",
        back_populates="ip_address",
        cascade="all, delete-orphan",
        order_by="Port.port_number",
    )


class Port(Base, TimestampMixin):
    """Порт, обнаруженный на хосте."""

    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("ip_address_id", "port_number", "protocol", name="uq_port_ip_number_protocol"),
        CheckConstraint("port_number >= 1 AND port_number <= 65535", name="ck_port_number_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    ip_address_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("host_ip_addresses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    port_number: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[Protocol] = mapped_column(Enum(Protocol, name="port_protocol"), nullable=False, default=Protocol.TCP)
    state: Mapped[PortState] = mapped_column(Enum(PortState, name="port_state"), nullable=False, default=PortState.OPEN)
    # HTTP-код ответа на корневой `/` (200/301/…), проставляется пробом «фермы».
    # null — порт не пробивался по HTTP или не ответил.
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)

    ip_address: Mapped["HostIpAddress"] = relationship("HostIpAddress", back_populates="ports")
    # Сервисы порта — нужны, чтобы отдавать имя сервиса вместе с портом одним
    # запросом (FK services.port_id уже есть, миграция не требуется).
    services: Mapped[list["Service"]] = relationship(
        "Service",
        cascade="all, delete-orphan",
        order_by="Service.name",
    )


class ProjectHiddenIp(Base):
    """Адрес, скрытый пользователем из списка IP проекта.

    «Удаление» IP из вкладки IP не должно рвать привязку адреса к домен-хостам
    (origin='host'): их HostIpAddress остаётся, и в карточке хоста адрес виден.
    Поэтому саму привязку не трогаем, а адрес заносим сюда — вкладка IP скрывает
    строки из этого списка. Отдельную IP-запись (Host origin='ip') при этом
    удаляем целиком. Явное повторное добавление через «Add IPs» убирает адрес
    отсюда (см. IpFarmService), и он снова показывается.
    """

    __tablename__ = "project_hidden_ips"
    __table_args__ = (
        UniqueConstraint("project_id", "ip_address", name="uq_project_hidden_ip"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    created_by: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Service(Base, TimestampMixin):
    """Сервис, работающий на порту."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    port_id: Mapped[int] = mapped_column(Integer, ForeignKey("ports.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)


class HostFarmJob(Base, TimestampMixin):
    """Фоновая задача рекон-фермы: пробив вставленного списка хостов или IP.

    Парсинг делается синхронно в запросе (быстро), а resolve+probe+persist идут в
    фоне; фронт опрашивает статус. ``result`` — сериализованный HostFarmResult
    либо IpFarmResult, в зависимости от ``kind``.
    """

    __tablename__ = "host_farm_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    # hosts | ips — какой фермой создана задача; определяет форму result.
    kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="hosts", server_default="hosts", index=True
    )
    # pending → queued → running → done | failed
    # pending ставит роутер, queued — relay воркера после публикации в RabbitMQ.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", server_default="pending", index=True)
    targets_total: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Сырой вставленный список — воркер живёт в другом процессе и получает
    # только id задачи, поэтому цели должны лежать в самой задаче.
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Ключи целей (hostname/IP), уже существовавших в проекте на момент постановки
    # задачи. Считаются синхронно в create_job (до skeleton-заготовок, иначе
    # заготовки этой же задачи выглядели бы как «уже добавленные»); воркер живёт в
    # другом процессе и получает только id, поэтому список должен лежать в задаче.
    # Воркер исключает эти цели из пробива — повторный импорт не пере-пробивает
    # уже добавленное, а только сообщает, сколько пропущено.
    skipped_targets: Mapped[list | None] = mapped_column(JSON, nullable=True)


class Endpoint(Base, TimestampMixin):
    """HTTP endpoint, связанный с хостом."""

    __tablename__ = "endpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[HttpMethod | None] = mapped_column(Enum(HttpMethod, name="http_method"), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_params: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    request_headers: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)


class JsFile(Base, TimestampMixin):
    """JS-файл, найденный и просканированный фермой на домене проекта.

    Ферма JS идёт на домен, находит `.js`, скачивает и грепает секреты + пути.
    Сам файл не хранится (скан в памяти) — в БД только находки и метаданные.
    Пути (`endpoints`) лежат JSON-списком: они навигационные и не подшиваются
    в таблицу endpoints. Секреты — отдельной таблицей JsSecret.
    """

    __tablename__ = "js_files"
    __table_args__ = (
        UniqueConstraint("project_id", "url", name="uq_js_file_project_url"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(127), nullable=True)
    # ok — скачан и просканирован; failed — не скачался; too_large — превысил лимит.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="ok", server_default="ok")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    endpoint_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    # Найденные в файле пути/URL: обычный JSON-список строк.
    endpoints: Mapped[list | None] = mapped_column(JSON, nullable=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    secrets: Mapped[list["JsSecret"]] = relationship(
        "JsSecret",
        back_populates="js_file",
        cascade="all, delete-orphan",
        order_by="JsSecret.id",
    )


class JsSecret(Base, TimestampMixin):
    """Секрет, найденный в JS-файле встроенным regex-набором."""

    __tablename__ = "js_secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    js_file_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("js_files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # aws_access_key | google_api | jwt | private_key | slack_token | github_pat | ...
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    # Усечённое/частично скрытое совпадение — полный секрет в БД не кладём.
    match_preview: Mapped[str] = mapped_column(String(255), nullable=False)
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    # high | medium | low
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium", server_default="medium")

    js_file: Mapped[JsFile] = relationship("JsFile", back_populates="secrets")


class Vulnerability(Base, TimestampMixin):
    """Найденная уязвимость."""

    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        # server_default = ИМЯ члена (SQLAlchemy Enum хранит имена, в верхнем
        # регистре — CRITICAL/HIGH/…/INFO). По умолчанию находка создаётся как INFO.
        Enum(Severity, name="vuln_severity"), nullable=False, default=Severity.INFO, server_default="INFO"
    )
    cvss_version: Mapped[CvssVersion | None] = mapped_column(Enum(CvssVersion, name="cvss_version"), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(4, 1), nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[VulnerabilityStatus] = mapped_column(
        Enum(VulnerabilityStatus, name="vuln_status"), nullable=False, default=VulnerabilityStatus.OPEN, index=True
    )
    workflow_steps: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    steps_to_reproduce: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)

    # Имя автора отдаём вместе с находкой: /users доступен только админу, а
    # «Reported by» видят все участники проекта.
    creator: Mapped["User"] = relationship("User", foreign_keys=[created_by], lazy="selectin")

    @property
    def created_by_username(self) -> str | None:
        """Имя автора находки для VulnerabilityOut."""
        return self.creator.username if self.creator else None


class VulnerabilityAsset(Base):
    """Полиморфная привязка уязвимости к активу."""

    __tablename__ = "vulnerability_assets"
    __table_args__ = (UniqueConstraint("vulnerability_id", "asset_type", "asset_id", name="uq_vuln_asset"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    asset_type: Mapped[AssetType] = mapped_column(Enum(AssetType, name="asset_type"), nullable=False)
    asset_id: Mapped[int] = mapped_column(Integer, nullable=False)


class JiraIssueLink(Base, TimestampMixin):
    """Связь уязвимости PCF с issue в Jira."""

    __tablename__ = "jira_issue_links"
    __table_args__ = (UniqueConstraint("vulnerability_id", name="uq_jira_issue_link_vulnerability"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    jira_issue_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    jira_issue_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="linked", server_default="linked")
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class File(Base):
    """Метаданные загруженного файла."""

    __tablename__ = "files"
    __table_args__ = (CheckConstraint("size_bytes <= 52428800", name="ck_file_max_size"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    original_name: Mapped[str] = mapped_column(String(500), nullable=False)
    content_type: Mapped[str] = mapped_column(String(127), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    minio_bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    minio_key: Mapped[str] = mapped_column(Text, nullable=False)
    uploaded_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Comment(Base, TimestampMixin):
    """Комментарий к уязвимости."""

    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class CommentMention(Base):
    """Упоминание пользователя в комментарии."""

    __tablename__ = "comment_mentions"
    __table_args__ = (UniqueConstraint("comment_id", "user_id", name="uq_comment_mention"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    comment_id: Mapped[int] = mapped_column(Integer, ForeignKey("comments.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)


class Notification(Base):
    """In-app уведомление."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type: Mapped[NotificationType] = mapped_column(
        Enum(NotificationType, name="notification_type"),
        nullable=False,
        default=NotificationType.MENTION,
    )
    comment_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("comments.id", ondelete="SET NULL"), nullable=True)
    # FK на комментарий заметки — для упоминаний (@username) в обсуждениях заметок.
    # Заполнен ровно у одного из двух (comment_id ИЛИ note_comment_id), не у обоих.
    note_comment_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("project_note_comments.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Предмет уведомления для не-mention поводов: добавление в проект и смена
    # статуса проекта ссылаются на project_id, смена статуса находки — на
    # vulnerability_id. У упоминаний оба пустые: их предмет — комментарий выше.
    project_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    vulnerability_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=True)
    # Кто инициировал событие и какой статус выставлен — чтобы не доставать из
    # аудита: уведомление должно быть самодостаточным даже после правок объекта.
    actor_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    """Запись журнала действий."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
