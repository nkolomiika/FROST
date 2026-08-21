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

# Базовый рантайм для api и mail-worker — без инструментов разведки.
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/app /usr/local/bin/app
USER app
ENTRYPOINT ["/usr/local/bin/app"]

# Рантайм recon-worker: тот же бинарь + внешние инструменты разведки.
#   nmap        — полный скан портов
#   subfinder   — пассивные поддомены
#   httpx-pd    — детект живости/технологий на портах (config: SERVICES_HTTPX_BIN=httpx-pd)
#   dnsx        — резолв
#   trufflehog  — verified-секреты в JS
FROM runtime AS recon
USER root
RUN apk add --no-cache nmap nmap-scripts
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=dnsx /usr/local/bin/dnsx /usr/local/bin/dnsx
COPY --from=subfinder /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=httpx /usr/local/bin/httpx /usr/local/bin/httpx-pd
# Тир-словари поддоменов (n0kovo_subdomains) для активного брута dnsx в полном
# прогоне фермы. Три тира → small|medium|large (см. WordlistPath в Go). Каталог
# переопределяется env RECON_WORDLIST_DIR (дефолт — этот). Скачивание
# устойчивое: -fSL, при отсутствии файла стадия брута деградирует, не падает.
RUN apk add --no-cache --virtual .wl-fetch wget \
    && mkdir -p /usr/local/share/frost-wordlists \
    && wget -qO /usr/local/share/frost-wordlists/n0kovo_subdomains_small.txt \
        https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt \
    && wget -qO /usr/local/share/frost-wordlists/n0kovo_subdomains_medium.txt \
        https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_medium.txt \
    && wget -qO /usr/local/share/frost-wordlists/n0kovo_subdomains_huge.txt \
        https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt \
    && apk del .wl-fetch
USER app
ENTRYPOINT ["/usr/local/bin/app"]
