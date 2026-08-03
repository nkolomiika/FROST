"""add QUERY to http_method

QUERY — метод из RFC-драфта httpbis: безопасный поиск с телом запроса.

Revision ID: d4e5f6a7b8c9
Revises: c7d8e9f0a1b2
Create Date: 2026-07-17 12:10:00.000000
"""
from alembic import op

# revision identifiers, used by Alembic.
revision = "d4e5f6a7b8c9"
down_revision = "c7d8e9f0a1b2"
branch_labels = None
depends_on = None

OLD_VALUES = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def upgrade() -> None:
    op.execute("ALTER TYPE http_method ADD VALUE IF NOT EXISTS 'QUERY'")


def downgrade() -> None:
    # Значение из enum не удалить — пересоздаём тип. Эндпоинты с QUERY теряют
    # метод (в старой схеме его не существует), сама запись остаётся.
    op.execute("UPDATE endpoints SET method = NULL WHERE method = 'QUERY'")
    values = ", ".join(f"'{value}'" for value in OLD_VALUES)
    op.execute(f"CREATE TYPE http_method_old AS ENUM ({values})")
    op.execute("ALTER TABLE endpoints ALTER COLUMN method TYPE http_method_old USING method::text::http_method_old")
    op.execute("DROP TYPE http_method")
    op.execute("ALTER TYPE http_method_old RENAME TO http_method")
