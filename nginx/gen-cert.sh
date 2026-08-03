#!/bin/sh
# Runs from nginx's /docker-entrypoint.d before nginx starts.
# Generates a self-signed cert on first boot if none exists.
#
# Dev (no env): CN=localhost, SAN=DNS:localhost,IP:127.0.0.1  — как раньше.
# Prod: pass CERT_IP and/or CERT_HOST (см. .env.prod + docker-compose.prod.yml),
#       и адрес попадёт в SAN, чтобы сертификат соответствовал URL. Браузер всё
#       равно предупредит про self-signed CA — это ожидаемо для self-signed.
set -e

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/selfsigned.crt"
KEY="$CERT_DIR/selfsigned.key"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
    command -v openssl >/dev/null 2>&1 || apk add --no-cache openssl
    mkdir -p "$CERT_DIR"

    # localhost/127.0.0.1 держим всегда (dev-доступ с самой машины по SSH-туннелю).
    SAN="DNS:localhost,IP:127.0.0.1"
    CN="localhost"
    if [ -n "$CERT_HOST" ]; then
        SAN="$SAN,DNS:$CERT_HOST"
        CN="$CERT_HOST"
    fi
    if [ -n "$CERT_IP" ]; then
        SAN="$SAN,IP:$CERT_IP"
        # CN по IP осмыслен, только если домена нет.
        [ -z "$CERT_HOST" ] && CN="$CERT_IP"
    fi

    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$KEY" -out "$CRT" \
        -subj "/CN=$CN" \
        -addext "subjectAltName=$SAN"
    echo "nginx: generated self-signed certificate (CN=$CN, SAN=$SAN)"
fi
