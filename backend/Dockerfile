FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmagic1 \
    whatweb \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# httpx (ProjectDiscovery) — определение технологий и CDN веб-порта. Быстрее и
# точнее whatweb, отдаёт стек + cdn_name одним batch-вызовом. Ставим prebuilt-бинарь
# под нужную архитектуру ПОД ИМЕНЕМ httpx-pd: pip-пакет httpx ставит свой
# консольный скрипт /usr/local/bin/httpx и затирает наш бинарь — отдельное имя
# снимает коллизию (см. services_httpx_bin в config.py).
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) HXA=amd64;; arm64) HXA=arm64;; *) HXA=amd64;; esac; \
    ver="$(curl -fsSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep -oP '\"tag_name\":\s*\"v\K[0-9.]+')"; \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${ver}/httpx_${ver}_linux_${HXA}.zip" -o /tmp/httpx.zip; \
    unzip -o /tmp/httpx.zip httpx -d /tmp/httpx-pd; \
    mv /tmp/httpx-pd/httpx /usr/local/bin/httpx-pd; \
    chmod +x /usr/local/bin/httpx-pd; \
    rm -rf /tmp/httpx.zip /tmp/httpx-pd; \
    httpx-pd -version

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Гарантируем наличие Pillow отдельной инструкцией, чтобы избежать ситуации,
# когда BuildKit возвращает закешированный слой `pip install`, собранный до
# добавления Pillow в requirements.txt (PIL нужен app.services для нормализации
# изображений в отчётах).
RUN pip install --no-cache-dir Pillow==10.4.0

COPY . /app

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
