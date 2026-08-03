"""host_farm_jobs.skipped_targets: цели, уже добавленные до постановки задачи

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-07-19 23:45:00.000000

NB: в dev-окружении alembic не запускается ничем (docker-compose поднимает
голый uvicorn), схему там накатывает блок startup() в app/main.py через
ADD COLUMN IF NOT EXISTS. Эта ревизия — для истории и для окружений, где
миграции прогоняются штатно; правки должны быть в обоих местах.
"""

import sqlalchemy as sa
from alembic import op

revision = "c3d4e5f6a7b8"
down_revision = "b2c3d4e5f6a7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ключи целей, уже существовавших в проекте на момент create_job. Воркер
    # исключает их из пробива — повторный импорт не пере-пробивает добавленное.
    op.add_column("host_farm_jobs", sa.Column("skipped_targets", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("host_farm_jobs", "skipped_targets")
