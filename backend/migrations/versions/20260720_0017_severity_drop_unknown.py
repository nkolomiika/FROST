"""drop UNKNOWN from vuln_severity; default severity → INFO

Критичность 'unknown' убрана: находка по умолчанию создаётся как INFO. Значение
из enum не удалить на месте — пересоздаём тип. Находки со снятым уровнем
('UNKNOWN' в верхнем регистре — как хранит SQLAlchemy, либо строчный дубль
'unknown' из ревизии b2c3d4e5f6a7) переводим в INFO.

Revision ID: e5f6a7b8c9d1
Revises: d4e5f6a7b8c9x
Create Date: 2026-07-20 01:00:00.000000

NB: в dev-окружении alembic не запускается — то же самое делает startup() в
app/main.py (UPDATE unknown→info + SET DEFAULT 'INFO'; висячую метку в типе там
не снимаем — ею никто не пишет). Правки должны быть в обоих местах.
"""

from alembic import op

revision = "e5f6a7b8c9d1"
down_revision = "d4e5f6a7b8c9x"
branch_labels = None
depends_on = None

NEW_VALUES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def upgrade() -> None:
    op.execute("UPDATE vulnerabilities SET severity = 'INFO' WHERE severity::text IN ('UNKNOWN', 'unknown')")
    values = ", ".join(f"'{value}'" for value in NEW_VALUES)
    op.execute(f"CREATE TYPE vuln_severity_new AS ENUM ({values})")
    op.execute("ALTER TABLE vulnerabilities ALTER COLUMN severity DROP DEFAULT")
    op.execute(
        "ALTER TABLE vulnerabilities ALTER COLUMN severity TYPE vuln_severity_new "
        "USING severity::text::vuln_severity_new"
    )
    op.execute("DROP TYPE vuln_severity")
    op.execute("ALTER TYPE vuln_severity_new RENAME TO vuln_severity")
    op.execute("ALTER TABLE vulnerabilities ALTER COLUMN severity SET DEFAULT 'INFO'")


def downgrade() -> None:
    # Возвращаем метку 'UNKNOWN' и прежний дефолт (данные не трогаем).
    op.execute("ALTER TYPE vuln_severity ADD VALUE IF NOT EXISTS 'UNKNOWN'")
    op.execute("ALTER TABLE vulnerabilities ALTER COLUMN severity SET DEFAULT 'UNKNOWN'")
