#!/usr/bin/env bash
# STORM — запуск в ПРОД-режиме (сервер, доступ по https://<адрес>).
#
# Отличие от дева — только окружение: prod читает .env.prod, dev читает .env.
# Код не меняется. Локальный дев запускается как обычно: `docker compose up -d`.
#
# Использование:
#   ./deploy.sh            — собрать и поднять прод-стек (up -d --build)
#   ./deploy.sh recreate   — то же + --force-recreate (подхватить правки .env.prod)
#   ./deploy.sh down       — остановить прод-стек
#   ./deploy.sh logs       — хвост логов backend/mail-worker/nginx
#   ./deploy.sh ps         — статус контейнеров
set -euo pipefail

cd "$(dirname "$0")"

ENV_PROD=".env.prod"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.prod.yml)

if [ ! -f "$ENV_PROD" ]; then
  echo "ОШИБКА: нет $ENV_PROD. Скопируйте шаблон и заполните:" >&2
  echo "  cp .env.prod.example .env.prod && \$EDITOR .env.prod" >&2
  exit 1
fi

# Значения для интерполяции в compose (nginx SAN). Берём только то, что нужно
# самому compose-файлу; всё остальное окружение контейнеры читают из ENV_FILE.
CERT_IP="$(grep -E '^CERT_IP=' "$ENV_PROD" | head -1 | cut -d= -f2- || true)"
CERT_HOST="$(grep -E '^CERT_HOST=' "$ENV_PROD" | head -1 | cut -d= -f2- || true)"
export CERT_IP CERT_HOST
export ENV_FILE="$ENV_PROD"

cmd="${1:-up}"
case "$cmd" in
  up|"")        "${COMPOSE[@]}" up -d --build ;;
  recreate)     "${COMPOSE[@]}" up -d --build --force-recreate ;;
  down)         "${COMPOSE[@]}" down ;;
  logs)         "${COMPOSE[@]}" logs -f --tail=100 backend mail-worker recon-worker nginx ;;
  ps)           "${COMPOSE[@]}" ps ;;
  *)            echo "неизвестная команда: $cmd (up|recreate|down|logs|ps)" >&2; exit 2 ;;
esac

if [ "$cmd" = "up" ] || [ "$cmd" = "recreate" ] || [ -z "$cmd" ]; then
  echo
  echo "STORM поднят в прод-режиме."
  addr="${CERT_HOST:-${CERT_IP:-<адрес-сервера>}}"
  echo "  Открывайте:  https://${addr}"
  echo "  Сертификат self-signed — браузер предупредит, это ожидаемо."
  echo "  Наружу должен смотреть только nginx (80/443). Порты 8000/9000/5433"
  echo "  закройте фаерволом Timeweb."
fi
