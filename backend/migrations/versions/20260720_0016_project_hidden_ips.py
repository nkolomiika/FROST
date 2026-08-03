"""project_hidden_ips — адреса, скрытые из списка IP проекта

Revision ID: d4e5f6a7b8c9x
Revises: c3d4e5f6a7b8
Create Date: 2026-07-20 09:00:00.000000

«Удаление» IP из вкладки IP не рвёт привязку адреса к домен-хостам: их
HostIpAddress остаётся (адрес виден в карточке хоста), а сам адрес заносится
сюда — вкладка IP скрывает строки из этого списка. Отдельную IP-запись
(Host origin='ip') при этом удаляем целиком. В dev alembic не запускается —
таблицу создаёт Base.metadata.create_all в startup(). Ревизия — для истории.
"""

import sqlalchemy as sa
from alembic import op

revision = "d4e5f6a7b8c9x"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "project_hidden_ips",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("project_id", "ip_address", name="uq_project_hidden_ip"),
    )
    op.create_index("ix_project_hidden_ips_project_id", "project_hidden_ips", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_project_hidden_ips_project_id", table_name="project_hidden_ips")
    op.drop_table("project_hidden_ips")
