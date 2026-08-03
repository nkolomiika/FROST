from fastapi import APIRouter, Cookie, Depends, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.dependencies import enforce_csrf, get_client_ip, get_current_user
from app.models import User
from app.schemas import (
    InvitationAcceptRequest,
    InvitationInfoOut,
    LoginRequest,
    LoginResponse,
    PasswordResetConfirmRequest,
    PasswordResetInfoOut,
    PasswordResetRequest,
    PasswordResetRequestOut,
    ReactivationInfoOut,
    RefreshResponse,
    TwoFAVerifyRequest,
    UsernameAvailabilityOut,
)
from app.security import TWO_FA_PENDING_TTL_MINUTES
from app.services import AuthService, UserService

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()

# Промежуточная cookie между шагами логина. Живёт коротко и ограничена путём /api/v1/auth.
TWO_FA_COOKIE = "twofa_token"
TWO_FA_COOKIE_PATH = "/api/v1/auth"


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Устанавливает access и refresh cookie в ответ."""
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_access_token_expire_minutes * 60,
        path="/",
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=settings.jwt_refresh_token_expire_days * 24 * 60 * 60,
        path="/api/v1/auth/refresh",
    )


def _clear_auth_cookies(response: Response) -> None:
    """Очищает auth-cookie в браузере."""
    response.set_cookie("access_token", "", httponly=True, secure=settings.cookie_secure, samesite=settings.cookie_samesite, max_age=0, path="/")
    response.set_cookie(
        "refresh_token",
        "",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=0,
        path="/api/v1/auth/refresh",
    )


def _set_twofa_cookie(response: Response, pending_token: str) -> None:
    """Ставит короткоживущую cookie для второго шага логина (ввод TOTP-кода)."""
    response.set_cookie(
        TWO_FA_COOKIE,
        pending_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=TWO_FA_PENDING_TTL_MINUTES * 60,
        path=TWO_FA_COOKIE_PATH,
    )


def _clear_twofa_cookie(response: Response) -> None:
    """Убирает промежуточную 2FA-cookie."""
    response.set_cookie(
        TWO_FA_COOKIE,
        "",
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        max_age=0,
        path=TWO_FA_COOKIE_PATH,
    )


@router.post("/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Первый шаг логина. При включённом 2FA возвращает challenge вместо сессии."""
    service = AuthService(db)
    outcome = await service.login(payload.username, payload.password, get_client_ip(request))
    if outcome.requires_2fa:
        _set_twofa_cookie(response, outcome.pending_token or "")
        response.status_code = status.HTTP_200_OK
        return LoginResponse(requires_2fa=True)
    _set_auth_cookies(response, outcome.access_token or "", outcome.refresh_token or "")
    response.status_code = status.HTTP_200_OK
    return LoginResponse(id=outcome.user.id, username=outcome.user.username, role=outcome.user.role)


@router.post("/2fa/verify", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def verify_2fa(
    payload: TwoFAVerifyRequest,
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    twofa_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Второй шаг логина: сверяет TOTP-код и выдаёт полноценную сессию."""
    service = AuthService(db)
    access_token, refresh_token, user = await service.verify_2fa(twofa_token, payload.code, get_client_ip(request))
    _set_auth_cookies(response, access_token, refresh_token)
    _clear_twofa_cookie(response)
    response.status_code = status.HTTP_200_OK
    return LoginResponse(id=user.id, username=user.username, role=user.role)


@router.get("/invitations/{token}", response_model=InvitationInfoOut)
async def invitation_info(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> InvitationInfoOut:
    """Публичная проверка ссылки-приглашения: валидна ли и на какой email."""
    info = await UserService(db).get_invitation_info(token)
    return InvitationInfoOut(**info)


@router.get("/invitations/{token}/username-available", response_model=UsernameAvailabilityOut)
async def invitation_username_available(
    token: str,
    username: str = Query(..., min_length=3, max_length=100),
    db: AsyncSession = Depends(get_db),
) -> UsernameAvailabilityOut:
    """Проверка занятости username на странице активации (нужен валидный токен)."""
    available = await UserService(db).check_invitation_username_available(token, username)
    return UsernameAvailabilityOut(available=available)


@router.post("/invitations/{token}/accept", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def accept_invitation(
    token: str,
    payload: InvitationAcceptRequest,
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Активация приглашения: приглашённый задаёт username+пароль и сразу входит."""
    service = UserService(db)
    user = await service.accept_invitation(token, payload.username, payload.password, get_client_ip(request))
    access_token, refresh_token = await AuthService(db).issue_session_for_user(user.id)
    _set_auth_cookies(response, access_token, refresh_token)
    response.status_code = status.HTTP_201_CREATED
    return LoginResponse(id=user.id, username=user.username, role=user.role)


@router.post("/password-reset/request", response_model=PasswordResetRequestOut, status_code=status.HTTP_200_OK)
async def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> PasswordResetRequestOut:
    """«Забыли пароль»: шлёт ссылку на email.

    Всегда отвечает 200, даже если такого пользователя нет — иначе по коду
    ответа можно было бы перебирать существующие адреса.
    """
    await UserService(db).request_password_reset(payload.email, get_client_ip(request))
    preview = settings.mail_preview_url if settings.smtp_host == "mailpit" else None
    return PasswordResetRequestOut(mail_preview_url=preview)


@router.get("/password-reset/{token}", response_model=PasswordResetInfoOut)
async def password_reset_info(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> PasswordResetInfoOut:
    """Проверяет ссылку до показа формы нового пароля."""
    return PasswordResetInfoOut(**await UserService(db).get_password_reset_info(token))


@router.post("/password-reset/{token}", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    token: str,
    payload: PasswordResetConfirmRequest,
    request: Request,
    response: Response,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Ставит новый пароль по ссылке. Сессию не выдаём — пользователь входит сам."""
    await UserService(db).confirm_password_reset(token, payload.password, get_client_ip(request))
    # Все сессии отозваны; чистим и cookie в текущем браузере, если они были.
    _clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/reactivate/{token}", response_model=ReactivationInfoOut)
async def reactivation_info(
    token: str,
    db: AsyncSession = Depends(get_db),
) -> ReactivationInfoOut:
    """Публичная проверка ссылки-возврата до показа кнопки входа."""
    return ReactivationInfoOut(**await UserService(db).get_reactivation_info(token))


@router.post("/reactivate/{token}", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def complete_reactivation(
    token: str,
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    db: AsyncSession = Depends(get_db),
) -> LoginResponse:
    """Возврат по ссылке: разблокирует аккаунт и сразу выдаёт сессию."""
    user = await UserService(db).complete_reactivation(token, get_client_ip(request))
    access_token, refresh_token = await AuthService(db).issue_session_for_user(user.id)
    _set_auth_cookies(response, access_token, refresh_token)
    response.status_code = status.HTTP_200_OK
    return LoginResponse(id=user.id, username=user.username, role=user.role)


@router.post("/refresh", response_model=RefreshResponse, status_code=status.HTTP_200_OK)
async def refresh(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    refresh_token: str | None = Cookie(default=None),
    db: AsyncSession = Depends(get_db),
) -> RefreshResponse:
    """Обновляет пару cookie-токенов с ротацией refresh-токена."""
    service = AuthService(db)
    new_access, new_refresh = await service.refresh(refresh_token, get_client_ip(request))
    _set_auth_cookies(response, new_access, new_refresh)
    response.status_code = status.HTTP_200_OK
    return RefreshResponse(ok=True)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    request: Request,
    _: None = Depends(enforce_csrf),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Отзывает токены и очищает cookie в браузере."""
    await AuthService(db).logout(current_user.id, get_client_ip(request))
    _clear_auth_cookies(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
