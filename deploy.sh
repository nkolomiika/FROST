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
read_env() { grep -E "^$1=" "$ENV_PROD" | head -1 | cut -d= -f2- || true; }

CERT_IP="$(read_env CERT_IP)"
CERT_HOST="$(read_env CERT_HOST)"
# Креды инфраструктуры: контейнеры postgres/minio читают их не из env_file,
# а из своего `environment`, поэтому compose должен подставить их сам.
POSTGRES_PASSWORD="$(read_env POSTGRES_PASSWORD)"
MINIO_ROOT_USER="$(read_env MINIO_ROOT_USER)"
MINIO_ROOT_PASSWORD="$(read_env MINIO_ROOT_PASSWORD)"
# MTU compose-сети (см. docker-compose.prod.yml).
DOCKER_NETWORK_MTU="$(read_env DOCKER_NETWORK_MTU)"
DOCKER_NETWORK_MTU="${DOCKER_NETWORK_MTU:-1500}"
export CERT_IP CERT_HOST POSTGRES_PASSWORD MINIO_ROOT_USER MINIO_ROOT_PASSWORD DOCKER_NETWORK_MTU
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
