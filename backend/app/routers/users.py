
from fastapi import APIRouter, Depends, File as FastAPIFile, Query, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user, require_admin
from app.models import User
from app.pagination import PageParams, to_paginated_response
from app.schemas import (
    InvitationCreate,
    InvitationOut,
    InvitationSentOut,
    OwnPasswordChangeRequest,
    PasswordResetOut,
    ReactivationRequestOut,
    TwoFAConfirmRequest,
    TwoFADisableRequest,
    TwoFASetupResponse,
    UserOut,
    UserProfileUpdate,
    UserUpdate,
)
from app.services import UserService

router = APIRouter(prefix="/users", tags=["users"])
settings = get_settings()


@router.get("/me", response_model=UserOut)
async def me(current_user: User = Depends(get_current_user)) -> User:
    """Возвращает профиль текущего пользователя."""
    return current_user


@router.get("/me/profile", response_model=UserOut)
async def my_profile(current_user: User = Depends(get_current_user)) -> User:
    """Возвращает расширенный профиль текущего пользователя."""
    return current_user


@router.patch("/me", response_model=UserOut)
async def update_my_profile(
    payload: UserProfileUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Обновляет профиль текущего пользователя."""
    user = await UserService(db).update_own_profile(current_user.id, payload.model_dump(exclude_unset=True), get_client_ip(request))
    return UserOut.model_validate(user)


@router.patch("/me/password", response_model=UserOut)
async def change_my_password(
    payload: OwnPasswordChangeRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Меняет пароль текущего пользователя."""
    user = await UserService(db).change_own_password(
        current_user.id,
        current_password=payload.current_password,
        new_password=payload.new_password,
        ip_address=get_client_ip(request),
    )
    return UserOut.model_validate(user)


@router.post("/me/2fa/setup", response_model=TwoFASetupResponse)
async def setup_my_2fa(
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> TwoFASetupResponse:
    """Готовит привязку 2FA: секрет + otpauth-URI + QR (data-URL). Ещё не включает."""
    secret, otpauth_uri, qr = await UserService(db).setup_2fa(current_user.id, get_client_ip(request))
    return TwoFASetupResponse(secret=secret, otpauth_uri=otpauth_uri, qr_png_data_url=qr)


@router.post("/me/2fa/confirm", response_model=UserOut)
async def confirm_my_2fa(
    payload: TwoFAConfirmRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Включает 2FA после ввода первого кода из приложения-аутентификатора."""
    user = await UserService(db).confirm_2fa(current_user.id, payload.code, get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/me/2fa/disable", response_model=UserOut)
async def disable_my_2fa(
    payload: TwoFADisableRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Отключает 2FA текущему пользователю (требует пароль аккаунта)."""
    user = await UserService(db).disable_2fa(current_user.id, payload.password, get_client_ip(request))
    return UserOut.model_validate(user)


@router.post("/me/avatar", response_model=UserOut)
async def upload_my_avatar(
    request: Request,
    avatar: UploadFile = FastAPIFile(...),
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Загружает новый аватар текущего пользователя."""
    user = await UserService(db).upload_avatar(current_user.id, avatar, get_client_ip(request))
    return UserOut.model_validate(user)


@router.get("", response_model=dict)
async def list_users(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Возвращает список пользователей для администратора."""
    items, total = await UserService(db).list_users(page, size)
    return to_paginated_response([UserOut.model_validate(it) for it in items], total, PageParams(page=page, size=size)).model_dump()


def _mail_preview_url() -> str | None:
    """URL веб-интерфейса mailpit — показываем в dev, чтобы админ увидел письмо."""
    return settings.mail_preview_url if settings.smtp_host == "mailpit" else None


@router.post("/invitations", response_model=InvitationSentOut, status_code=status.HTTP_201_CREATED)
async def create_invitation(
    payload: InvitationCreate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> InvitationSentOut:
    """Приглашает пользователя по email: шлёт ссылку активации, User создаётся при активации."""
    invitation, _job = await UserService(db).create_invitation(payload.model_dump(), admin.id, get_client_ip(request))
    return InvitationSentOut(
        invitation=InvitationOut.model_validate(invitation),
        email_sent_to=invitation.email,
        mail_preview_url=_mail_preview_url(),
    )


@router.get("/invitations", response_model=list[InvitationOut])
async def list_invitations(
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[InvitationOut]:
    """Список незавершённых приглашений (pending, в т.ч. истёкших)."""
    items = await UserService(db).list_invitations()
    return [InvitationOut.model_validate(item) for item in items]


@router.post("/invitations/{invitation_id}/resend", response_model=InvitationSentOut)
async def resend_invitation(
    invitation_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> InvitationSentOut:
    """Перевыпускает ссылку приглашения и отправляет письмо заново."""
    invitation, _job = await UserService(db).resend_invitation(invitation_id, admin.id, get_client_ip(request))
    return InvitationSentOut(
        invitation=InvitationOut.model_validate(invitation),
        email_sent_to=invitation.email,
        mail_preview_url=_mail_preview_url(),
    )


@router.delete("/invitations/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_invitation(
    invitation_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Отзывает приглашение — ссылка перестаёт работать."""
    await UserService(db).revoke_invitation(invitation_id, admin.id, get_client_ip(request))


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int,
    _admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Возвращает пользователя по ID."""
    user = await UserService(db).get_user(user_id)
    return UserOut.model_validate(user)


@router.get("/{user_id}/avatar")
async def get_user_avatar(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Возвращает аватар пользователя."""
    service = UserService(db)
    service.ensure_can_view_avatar(current_user, user_id)
    user, content = await service.download_avatar(user_id)
    return Response(content=content, media_type=user.avatar_content_type or "application/octet-stream")


@router.put("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Обновляет пользователя."""
    user = await UserService(db).update_user(user_id, payload.model_dump(exclude_unset=True), admin.id, get_client_ip(request))
    return UserOut.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Деактивирует пользователя (мягкое удаление: is_locked, строка сохраняется)."""
    await UserService(db).delete_user(user_id, admin.id, get_client_ip(request))


@router.post("/{user_id}/reactivate", response_model=ReactivationRequestOut, status_code=status.HTTP_200_OK)
async def reactivate_user(
    user_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ReactivationRequestOut:
    """Возвращает деактивированного пользователя: шлёт ему письмо-возврат со ссылкой.

    Аккаунт разблокируется не здесь, а когда пользователь сам перейдёт по ссылке
    (там же сразу выдаётся сессия — см. /auth/reactivate).
    """
    mail_job = await UserService(db).request_reactivation(user_id, admin.id, get_client_ip(request))
    preview_url = settings.mail_preview_url if settings.smtp_host == "mailpit" else None
    return ReactivationRequestOut(email_sent_to=mail_job.recipient_email, mail_preview_url=preview_url)


@router.patch("/{user_id}/password", response_model=PasswordResetOut, status_code=status.HTTP_200_OK)
async def reset_password(
    user_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PasswordResetOut:
    """Сбрасывает пароль пользователя."""
    user = await UserService(db).reset_password(user_id, admin.id, get_client_ip(request))
    preview_url = settings.mail_preview_url if settings.smtp_host == "mailpit" else None
    return PasswordResetOut(email_sent_to=user.email, mail_preview_url=preview_url)


@router.post("/{user_id}/2fa/reset", response_model=UserOut, status_code=status.HTTP_200_OK)
async def reset_2fa(
    user_id: int,
    request: Request,
    _: None = Depends(enforce_csrf),
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> UserOut:
    """Сбрасывает 2FA пользователю (например, при потере телефона)."""
    user = await UserService(db).admin_reset_2fa(user_id, admin.id, get_client_ip(request))
    return UserOut.model_validate(user)
