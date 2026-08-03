from math import ceil
from typing import Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PageParams(BaseModel):
    """Параметры offset-пагинации.

    Верхняя граница совпадает с самой большой `le=` в роутах
    (например, `GET /projects` отдаёт до 1000 для admin-диалогов выбора всех
    проектов в API-токенах). Раньше тут стоял `le=200`, из-за чего роут с
    `le=1000` отдавал 500 при `size>200` на этапе сборки PaginatedResponse.
    """

    page: int = Field(default=1, ge=1)
    size: int = Field(default=20, ge=1, le=1000)

    @property
    def offset(self) -> int:
        """Смещение для SQL-запроса."""
        return (self.page - 1) * self.size


class PaginatedResponse(BaseModel, Generic[T]):
    """Унифицированный ответ пагинированных эндпоинтов."""

    items: list[T]
    total: int
    page: int
    size: int
    pages: int


def to_paginated_response(items: list[T], total: int, params: PageParams) -> PaginatedResponse[T]:
    """Собирает объект пагинации по данным и параметрам страницы."""
    pages = max(1, ceil(total / params.size)) if total > 0 else 1
    return PaginatedResponse[T](
        items=items,
        total=total,
        page=params.page,
        size=params.size,
        pages=pages,
    )
