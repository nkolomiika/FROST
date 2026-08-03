"""host farm: ports.http_status + host_farm_jobs

Ферма пентестера: серверный пробив вставленного списка хостов. Добавляет HTTP-код
ответа на порт (ports.http_status) и таблицу фоновых задач пробива (host_farm_jobs).

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-19 12:00:00.000000
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ports", sa.Column("http_status", sa.Integer(), nullable=True))
    op.create_table(
        "host_farm_jobs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="running", nullable=False),
        sa.Column("targets_total", sa.Integer(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_host_farm_jobs_project_id", "host_farm_jobs", ["project_id"])
    op.create_index("ix_host_farm_jobs_status", "host_farm_jobs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_host_farm_jobs_status", table_name="host_farm_jobs")
    op.drop_index("ix_host_farm_jobs_project_id", table_name="host_farm_jobs")
    op.drop_table("host_farm_jobs")
    op.drop_column("ports", "http_status")
