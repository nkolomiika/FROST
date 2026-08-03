"""account_reactivation_tokens — ссылки возврата деактивированных пользователей

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-07-19 19:00:00.000000

Одноразовый токен возврата: админ «удаляет» (блокирует) пользователя, а вернуть
доступ можно только по ссылке из письма — переход по ней разблокирует аккаунт и
сразу выдаёт сессию. В БД, как и для сброса пароля, лежит только SHA-256 токена.
В dev alembic не запускается — таблицу создаёт Base.metadata.create_all в
startup() (новые ТАБЛИЦЫ покрываются им целиком). Ревизия — для истории.
"""

import sqlalchemy as sa
from alembic import op

revision = "a8b9c0d1e2f3"
down_revision = "f7a8b9c0d1e2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "account_reactivation_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_account_reactivation_tokens_user_id", "account_reactivation_tokens", ["user_id"])
    op.create_index(
        "ix_account_reactivation_tokens_token_hash", "account_reactivation_tokens", ["token_hash"], unique=True
    )


def downgrade() -> None:
    op.drop_index("ix_account_reactivation_tokens_token_hash", table_name="account_reactivation_tokens")
    op.drop_index("ix_account_reactivation_tokens_user_id", table_name="account_reactivation_tokens")
    op.drop_table("account_reactivation_tokens")
