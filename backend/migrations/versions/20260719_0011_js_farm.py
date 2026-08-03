"""js farm: js_files + js_secrets

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-19 15:00:00.000000

Новые таблицы под ферму JS (поиск секретов и путей в .js доменов проекта). В
dev alembic не запускается — таблицы создаёт Base.metadata.create_all в
startup() (новые ТАБЛИЦЫ покрываются им целиком, в отличие от новых колонок).
Ревизия — для истории и штатных окружений.
"""

import sqlalchemy as sa
from alembic import op

revision = "e5f6a7b8c9d0"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "js_files",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=127), nullable=True),
        sa.Column("status", sa.String(length=16), server_default="ok", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("secret_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("endpoint_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("endpoints", sa.JSON(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "url", name="uq_js_file_project_url"),
    )
    op.create_index("ix_js_files_project_id", "js_files", ["project_id"])
    op.create_index("ix_js_files_host_id", "js_files", ["host_id"])

    op.create_table(
        "js_secrets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("js_file_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False),
        sa.Column("match_preview", sa.String(length=255), nullable=False),
        sa.Column("snippet", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=16), server_default="medium", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["js_file_id"], ["js_files.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_js_secrets_js_file_id", "js_secrets", ["js_file_id"])


def downgrade() -> None:
    op.drop_index("ix_js_secrets_js_file_id", table_name="js_secrets")
    op.drop_table("js_secrets")
    op.drop_index("ix_js_files_host_id", table_name="js_files")
    op.drop_index("ix_js_files_project_id", table_name="js_files")
    op.drop_table("js_files")
