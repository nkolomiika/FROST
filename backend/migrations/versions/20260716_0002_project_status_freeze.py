"""add FREEZE to project_status

Статус «заморожен»: работы по проекту приостановлены — он уже не активен, но и
не завершён.

Revision ID: b1f2c3d4e5a6
Revises: 66377caf493e
Create Date: 2026-07-16 21:05:00.000000
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "b1f2c3d4e5a6"
down_revision = "66377caf493e"
branch_labels = None
depends_on = None

# В БД enum хранится именами членов (sa.Enum('ACTIVE', ...)), не значениями.
NEW_VALUE = "FREEZE"
OLD_VALUES = ("ACTIVE", "HANDOVER_TO_DEVELOPMENT", "VULNERABILITY_RECHECK", "COMPLETED", "ARCHIVED")


def upgrade() -> None:
    # PostgreSQL 12+ разрешает ADD VALUE внутри транзакции, если новое значение
    # в этой же транзакции не используется. IF NOT EXISTS — чтобы повтор был безопасен.
    op.execute(f"ALTER TYPE project_status ADD VALUE IF NOT EXISTS '{NEW_VALUE}' AFTER 'ACTIVE'")


def downgrade() -> None:
    # Удалить значение из enum нельзя — тип пересоздаём. Проекты со статусом FREEZE
    # возвращаем в ACTIVE, иначе приведение типа упадёт.
    op.execute(f"UPDATE projects SET status = 'ACTIVE' WHERE status = '{NEW_VALUE}'")
    values = ", ".join(f"'{value}'" for value in OLD_VALUES)
    op.execute(f"CREATE TYPE project_status_old AS ENUM ({values})")
    op.execute(
        "ALTER TABLE projects ALTER COLUMN status TYPE project_status_old "
        "USING status::text::project_status_old"
    )
    op.execute("DROP TYPE project_status")
    op.execute("ALTER TYPE project_status_old RENAME TO project_status")
