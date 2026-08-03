"""Экспортирует OpenAPI/Swagger-спецификации в статические JSON-файлы.

Зачем: FastAPI отдаёт `/openapi.json` в runtime, но статический файл удобен для
ревью PR, offline-чтения, импорта в Postman/Insomnia, CI-проверок diff'а.

Запуск:
    # из корня репозитория
    docker compose run --rm backend python -m scripts.export_openapi

    # либо локально (нужен Python 3.12 и установленные requirements)
    cd backend
    python -m scripts.export_openapi

Файлы сохраняются в `docs/openapi-v1.json` и `docs/openapi-v2.json`
(относительно корня репо).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Гарантируем, что `backend/` в sys.path — скрипт может быть запущен
# и как модуль (`python -m scripts.export_openapi`), и напрямую.
_backend_root = Path(__file__).resolve().parents[1]
if str(_backend_root) not in sys.path:
    sys.path.insert(0, str(_backend_root))

from app.main import agent_api_v2, app  # noqa: E402


def _dump(spec: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys=False — сохраняем порядок секций как у FastAPI (info → paths → components).
    # indent=2 + final newline — diff-friendly.
    path.write_text(json.dumps(spec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    repo_root = _backend_root.parent
    docs_dir = repo_root / "docs"

    v1_path = docs_dir / "openapi-v1.json"
    v2_path = docs_dir / "openapi-v2.json"

    v1_spec = app.openapi()
    v2_spec = agent_api_v2.openapi()

    _dump(v1_spec, v1_path)
    _dump(v2_spec, v2_path)

    print(f"[ok] {v1_path.relative_to(repo_root)} — {len(v1_spec.get('paths', {}))} endpoints")
    print(f"[ok] {v2_path.relative_to(repo_root)} — {len(v2_spec.get('paths', {}))} endpoints")
    return 0


if __name__ == "__main__":
    sys.exit(main())
