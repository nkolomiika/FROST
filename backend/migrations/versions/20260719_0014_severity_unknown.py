"""add UNKNOWN to vuln_severity

Критичность новой находки по умолчанию не определена (нет CVSS-вектора).
Значение уточняется автором позже.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-07-19 23:55:00.000000

NB: в dev-окружении alembic не запускается — схему накатывает startup() в
app/main.py через ALTER TYPE ... ADD VALUE IF NOT EXISTS. Правки должны быть
в обоих местах.
"""
from alembic import op

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None

OLD_VALUES = ("critical", "high", "medium", "low", "info")


def upgrade() -> None:
    op.execute("ALTER TYPE vuln_severity ADD VALUE IF NOT EXISTS 'unknown'")


def downgrade() -> None:
    # Значение из enum не удалить — пересоздаём тип. Находки с severity='unknown'
    # переводим в 'info' (в старой схеме 'unknown' не существует).
    op.execute("UPDATE vulnerabilities SET severity = 'info' WHERE severity = 'unknown'")
    values = ", ".join(f"'{value}'" for value in OLD_VALUES)
    op.execute(f"CREATE TYPE vuln_severity_old AS ENUM ({values})")
    op.execute(
        "ALTER TABLE vulnerabilities ALTER COLUMN severity DROP DEFAULT"
    )
    op.execute(
        "ALTER TABLE vulnerabilities ALTER COLUMN severity TYPE vuln_severity_old "
        "USING severity::text::vuln_severity_old"
    )
    op.execute("DROP TYPE vuln_severity")
    op.execute("ALTER TYPE vuln_severity_old RENAME TO vuln_severity")
