"""ip farm: hosts.origin, host_ip_addresses.hostnames/is_cloudflare, host_farm_jobs.kind

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-19 13:00:00.000000

NB: в dev-окружении alembic не запускается ничем (docker-compose поднимает
голый uvicorn), схему там накатывает блок startup() в app/main.py через
ADD COLUMN IF NOT EXISTS. Эта ревизия — для истории и для окружений, где
миграции прогоняются штатно; правки должны быть в обоих местах.
"""

import sqlalchemy as sa
from alembic import op

revision = "d4e5f6a7b8c9"
down_revision = "c3d4e5f6a7b8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Происхождение хоста: 'ip' — служебный родитель адреса из фермы IP, в
    # списке хостов не показывается. По hostname IS NULL их отличить нельзя:
    # ферма хостов тоже пишет NULL для вставленного IP-литерала.
    op.add_column("hosts", sa.Column("origin", sa.String(length=16), server_default="host", nullable=False))
    op.create_index("ix_hosts_origin", "hosts", ["origin"])

    op.add_column("host_ip_addresses", sa.Column("hostnames", sa.JSON(), nullable=True))
    op.add_column(
        "host_ip_addresses",
        sa.Column("is_cloudflare", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.execute("UPDATE host_ip_addresses SET hostnames = '[]'")

    # Одна таблица задач на обе фермы + поля очереди (см. app/worker/recon_worker.py).
    op.add_column("host_farm_jobs", sa.Column("kind", sa.String(length=16), server_default="hosts", nullable=False))
    op.create_index("ix_host_farm_jobs_kind", "host_farm_jobs", ["kind"])
    op.add_column("host_farm_jobs", sa.Column("raw", sa.Text(), nullable=True))
    op.add_column("host_farm_jobs", sa.Column("attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column("host_farm_jobs", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("host_farm_jobs", sa.Column("last_error", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("host_farm_jobs", "last_error")
    op.drop_column("host_farm_jobs", "published_at")
    op.drop_column("host_farm_jobs", "attempts")
    op.drop_column("host_farm_jobs", "raw")
    op.drop_index("ix_host_farm_jobs_kind", table_name="host_farm_jobs")
    op.drop_column("host_farm_jobs", "kind")
    op.drop_column("host_ip_addresses", "is_cloudflare")
    op.drop_column("host_ip_addresses", "hostnames")
    op.drop_index("ix_hosts_origin", table_name="hosts")
    op.drop_column("hosts", "origin")
