"""user is_locked (мягкое удаление / деактивация)

Revision ID: f7a8b9c0d1e2
Revises: e5f6a7b8c9d0
Create Date: 2026-07-19 18:00:00.000000

Флаг административной блокировки пользователя. «Удаление» пользователя больше не
стирает строку (за ней тянутся его проекты/находки/заметки по FK RESTRICT, отсюда
и падало 500) — вместо этого выставляется is_locked=true: вход запрещён, но всё
авторство и связи сохраняются. В dev alembic не запускается — колонку добавляет
идемпотентный ALTER ... ADD COLUMN IF NOT EXISTS в startup(); ревизия — для
истории и штатных окружений.
"""

import sqlalchemy as sa
from alembic import op

revision = "f7a8b9c0d1e2"
down_revision = "e5f6a7b8c9d0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_locked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("users", "is_locked")
