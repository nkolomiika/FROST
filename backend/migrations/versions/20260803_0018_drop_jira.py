"""drop jira — удаление интеграции с Jira

Revision ID: a9b0c1d2e3f4
Revises: e5f6a7b8c9d1
Create Date: 2026-08-03 12:00:00.000000

Экспорт уязвимостей в Jira убран из продукта целиком (роутер, сервис, схемы,
модели). Здесь сносим три оставшиеся таблицы: глобальный конфиг подключения,
привязку проекта к Jira project key и связь уязвимости с созданной issue.
downgrade воссоздаёт их пустыми — данные не восстанавливаются.
"""

import sqlalchemy as sa
from alembic import op

revision = "a9b0c1d2e3f4"
down_revision = "e5f6a7b8c9d1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index(op.f("ix_jira_issue_links_vulnerability_id"), table_name="jira_issue_links")
    op.drop_index(op.f("ix_jira_issue_links_jira_issue_key"), table_name="jira_issue_links")
    op.drop_table("jira_issue_links")
    op.drop_table("project_jira_links")
    op.drop_table("jira_instances")


def downgrade() -> None:
    op.create_table(
        "jira_instances",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), server_default="default", nullable=False),
        sa.Column("base_url", sa.String(length=1024), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("api_token_encrypted", sa.Text(), nullable=False),
        sa.Column("default_issue_type", sa.String(length=100), server_default="Task", nullable=False),
        sa.Column("is_enabled", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "project_jira_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("jira_project_key", sa.String(length=32), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", name="uq_project_jira_link_project"),
    )
    op.create_table(
        "jira_issue_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("vulnerability_id", sa.Integer(), nullable=False),
        sa.Column("jira_issue_key", sa.String(length=64), nullable=False),
        sa.Column("jira_issue_url", sa.String(length=1024), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="linked", nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("vulnerability_id", name="uq_jira_issue_link_vulnerability"),
    )
    op.create_index(op.f("ix_jira_issue_links_jira_issue_key"), "jira_issue_links", ["jira_issue_key"], unique=False)
    op.create_index(op.f("ix_jira_issue_links_vulnerability_id"), "jira_issue_links", ["vulnerability_id"], unique=False)
