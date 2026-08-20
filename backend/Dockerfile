# Python reports-sidecar (интерим Go-миграции): генерирует Word-отчёты через
# проверенный word_builder. Основной бэкенд — Go (../backend-go). Образ намеренно
# минимален: только зависимости word_builder + его модельная цепочка.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

# По умолчанию — sidecar; docker-compose монтирует код и переопределяет команду.
CMD ["uvicorn", "app.report_sidecar:app", "--host", "0.0.0.0", "--port", "8100"]
