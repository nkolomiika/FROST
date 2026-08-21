# Многоступенчатая сборка Go-бинарей FROST. Один образ собирает все cmd/,
# конкретный бинарь выбирается через build-arg CMD (api | mail-worker | recon-worker).
FROM golang:1.26-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG CMD=api
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./cmd/${CMD}

# Recon-worker дополнительно везёт внешние инструменты разведки: trufflehog
# (verified-секреты) и dnsx (резолв) — оба чистый Go, CGO не нужен. Ставятся
# только для recon-worker; пустой /out/tools у остальных делает COPY безопасным.
# (jsluice тянет tree-sitter/CGO — добавим отдельным шагом.)
RUN mkdir -p /out/tools && if [ "$CMD" = "recon-worker" ]; then \
      GOBIN=/out/tools CGO_ENABLED=0 go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
      GOBIN=/out/tools CGO_ENABLED=0 go install github.com/trufflesecurity/trufflehog/v3@latest ; \
    fi

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/app /usr/local/bin/app
COPY --from=build /out/tools/ /usr/local/bin/
USER app
ENTRYPOINT ["/usr/local/bin/app"]
