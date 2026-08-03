class PCFError(Exception):
    """Базовое исключение приложения."""


class NotFoundError(PCFError):
    """Сущность не найдена."""


class ForbiddenError(PCFError):
    """Доступ запрещён."""


class ConflictError(PCFError):
    """Конфликт данных."""


class UnauthorizedError(PCFError):
    """Ошибка аутентификации."""


class ValidationError(PCFError):
    """Ошибка бизнес-валидации."""
