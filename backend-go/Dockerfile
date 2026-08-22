# Многоступенчатая сборка Go-бинарей FROST. Один образ собирает все cmd/,
# конкретный бинарь выбирается через build-arg CMD (api | mail-worker | recon-worker).
# Финальный образ выбирается через build target: `runtime` (api/mail) или `recon`
# (recon-worker — дополнительно везёт инструменты разведки).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD=api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# Готовые статические бинари инструментов из официальных образов (без компиляции).
FROM trufflesecurity/trufflehog:latest AS trufflehog
FROM projectdiscovery/dnsx:latest AS dnsx
FROM projectdiscovery/subfinder:latest AS subfinder
FROM projectdiscovery/httpx:latest AS httpx
FROM projectdiscovery/katana:latest AS katana

# gau, waybackurls и ffuf не публикуют официальных образов — собираем их статически
# в Go-стадии (все чистый Go) и COPY-им бинари в recon-стейдж.
FROM golang:1.26-alpine AS endpoint-tools
RUN apk add --no-cache git \
 && GOBIN=/out CGO_ENABLED=0 go install github.com/lc/gau/v2/cmd/gau@latest \
 && GOBIN=/out CGO_ENABLED=0 go install github.com/tomnomnom/waybackurls@latest \
 && GOBIN=/out CGO_ENABLED=0 go install github.com/ffuf/ffuf/v2@latest

# Базовый рантайм для api и mail-worker — без инструментов разведки.
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/app /usr/local/bin/app
# Забандленные словари (n0kovo тиры + курируемый SecLists) — в БАЗОВОМ рантайме,
# чтобы их видел И api-контейнер (эндпоинт GET /recon/wordlists перечисляет их через
# EnumerateWordlists), И recon-worker (использует для dnsx/ffuf). Один раз качаем
# здесь; recon-стейдж наследует. Каталог переопределяется env RECON_WORDLIST_DIR.
RUN apk add --no-cache --virtual .wl-fetch wget; \
    mkdir -p /usr/local/share/frost-wordlists; \
    for tier in small medium huge; do \
      f="/usr/local/share/frost-wordlists/n0kovo_subdomains_${tier}.txt"; \
      if wget -q --tries=3 --timeout=45 -O "$f" \
        "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_${tier}.txt" \
        && [ -s "$f" ]; then \
        echo "wordlist ${tier}: ok ($(wc -c < "$f") bytes)"; \
      else \
        echo "WARN: wordlist ${tier} download failed — active brute will self-skip this tier"; \
        rm -f "$f"; \
      fi; \
    done; \
    for rel in \
      Discovery/DNS/subdomains-top1million-5000.txt \
      Discovery/DNS/subdomains-top1million-20000.txt \
      Discovery/DNS/subdomains-top1million-110000.txt \
      Discovery/DNS/bitquark-subdomains-top100000.txt \
      Discovery/Web-Content/directory-list-2.3-small.txt \
      Discovery/Web-Content/directory-list-2.3-medium.txt \
      Discovery/Web-Content/raft-medium-directories.txt \
      Discovery/Web-Content/raft-medium-files.txt \
      Discovery/Web-Content/common.txt \
      Discovery/Web-Content/raft-large-directories.txt \
    ; do \
      dst="/usr/local/share/frost-wordlists/seclists/${rel}"; \
      mkdir -p "$(dirname "$dst")"; \
      if wget -q --tries=3 --timeout=45 -O "$dst" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/${rel}" \
        && [ -s "$dst" ]; then \
        echo "seclists ${rel}: ok ($(wc -c < "$dst") bytes)"; \
      else \
        echo "WARN: seclists ${rel} download failed — file will be absent from the picker"; \
        rm -f "$dst"; \
      fi; \
    done; \
    apk del .wl-fetch

USER app
ENTRYPOINT ["/usr/local/bin/app"]

# Рантайм recon-worker: тот же бинарь + внешние инструменты разведки.
#   nmap        — полный скан портов
#   subfinder   — пассивные поддомены
#   httpx-pd    — детект живости/технологий на портах (config: SERVICES_HTTPX_BIN=httpx-pd)
#   dnsx        — резолв
#   trufflehog  — verified-секреты в JS
#   katana      — активный краул URL (стадия эндпоинтов)
#   gau         — архивные URL (стадия эндпоинтов)
#   waybackurls — URL из Wayback Machine (стадия эндпоинтов)
#   ffuf        — активный дир-фаззинг (стадия эндпоинтов, active/both режим)
FROM runtime AS recon
USER root
# apk-зеркало Alpine на buildkit сервера периодически флапает ("temporary error").
# nmap обязателен для recon-образа, поэтому тянем с ретраями, а не одним заходом —
# иначе разовый сетевой сбой роняет всю пересборку стека.
RUN for i in 1 2 3 4 5 6; do \
      apk add --no-cache nmap nmap-scripts && break; \
      echo "apk nmap: attempt $i failed, retrying in 5s"; sleep 5; \
    done; \
    command -v nmap >/dev/null 2>&1 || { echo "FATAL: nmap install failed after retries"; exit 1; }
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
# Кастомные детекторы trufflehog (UUID и пр.) — путь совпадает с TRUFFLEHOG_CONFIG.
COPY deploy/trufflehog-custom.yaml /usr/local/share/frost/trufflehog-custom.yaml
COPY --from=dnsx /usr/local/bin/dnsx /usr/local/bin/dnsx
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx-pd
COPY --from=katana /usr/local/bin/katana /usr/local/bin/katana
COPY --from=endpoint-tools /out/gau /usr/local/bin/gau
COPY --from=endpoint-tools /out/waybackurls /usr/local/bin/waybackurls
COPY --from=endpoint-tools /out/ffuf /usr/local/bin/ffuf
USER app
ENTRYPOINT ["/usr/local/bin/app"]
