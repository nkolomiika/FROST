"""notification kinds beyond @mention

Уведомления теперь бывают четырёх видов: упоминание, добавление в проект, смена
статуса своей находки и смена статуса проекта. Для трёх новых нужен предмет
(project_id / vulnerability_id), инициатор и выставленный статус.

Revision ID: c7d8e9f0a1b2
Revises: b1f2c3d4e5a6
Create Date: 2026-07-17 10:40:00.000000
"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c7d8e9f0a1b2"
down_revision = "b1f2c3d4e5a6"
branch_labels = None
depends_on = None

# В БД enum хранится именами членов (sa.Enum('MENTION', ...)), не значениями.
NEW_TYPES = ("PROJECT_MEMBER_ADDED", "VULN_STATUS_CHANGED", "PROJECT_STATUS_CHANGED")


def upgrade() -> None:
    for name in NEW_TYPES:
        op.execute(f"ALTER TYPE notification_type ADD VALUE IF NOT EXISTS '{name}'")
    op.add_column("notifications", sa.Column("project_id", sa.Integer(), nullable=True))
    op.add_column("notifications", sa.Column("vulnerability_id", sa.Integer(), nullable=True))
    op.add_column("notifications", sa.Column("actor_id", sa.Integer(), nullable=True))
    op.add_column("notifications", sa.Column("status", sa.String(length=50), nullable=True))
    op.create_foreign_key("fk_notifications_project", "notifications", "projects", ["project_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("fk_notifications_vulnerability", "notifications", "vulnerabilities", ["vulnerability_id"], ["id"], ondelete="CASCADE")
    op.create_foreign_key("fk_notifications_actor", "notifications", "users", ["actor_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    op.drop_constraint("fk_notifications_actor", "notifications", type_="foreignkey")
    op.drop_constraint("fk_notifications_vulnerability", "notifications", type_="foreignkey")
    op.drop_constraint("fk_notifications_project", "notifications", type_="foreignkey")
    op.drop_column("notifications", "status")
    op.drop_column("notifications", "actor_id")
    op.drop_column("notifications", "vulnerability_id")
    op.drop_column("notifications", "project_id")
    # Значения enum удалить нельзя — пересоздаём тип. Уведомления новых видов
    # при откате исчезают: в старой схеме их нечем описать.
    op.execute("DELETE FROM notifications WHERE type::text <> 'MENTION'")
    op.execute("CREATE TYPE notification_type_old AS ENUM ('MENTION')")
    op.execute(
        "ALTER TABLE notifications ALTER COLUMN type TYPE notification_type_old "
        "USING type::text::notification_type_old"
    )
    op.execute("DROP TYPE notification_type")
    op.execute("ALTER TYPE notification_type_old RENAME TO notification_type")
