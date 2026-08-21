# Многоступенчатая сборка Go-бинарей FROST. Один образ собирает все cmd/,
# конкретный бинарь выбирается через build-arg CMD (api | mail-worker | recon-worker).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD=api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# Инструменты разведки для recon-worker — берём готовые статические бинари из
# официальных образов (никакой компиляции и скачивания модулей в сборке, что
# раньше падало на flaky build-сети). trufflehog — verified-секреты, dnsx — резолв.
FROM trufflesecurity/trufflehog:latest AS trufflehog
FROM projectdiscovery/dnsx:latest AS dnsx

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/app /usr/local/bin/app
COPY --from=trufflehog /usr/bin/trufflehog /usr/local/bin/trufflehog
COPY --from=dnsx /usr/local/bin/dnsx /usr/local/bin/dnsx
USER app
ENTRYPOINT ["/usr/local/bin/app"]
