FROM node:22-alpine

# Node резолвит AAAA первым. Хостинг с объявленным, но нерабочим IPv6-маршрутом
# (RA даёт default route, трафик не ходит) вешает npm на ETIMEDOUT к registry,
# хотя обычный HTTPS по IPv4 из того же контейнера работает. Порядок резолва
# фиксируем на IPv4 — на машинах с рабочим IPv6 это ничего не ломает.
ENV NODE_OPTIONS=--dns-result-order=ipv4first

# npm по умолчанию тянет пакеты в 15 сокетов и сдаётся после 2 ретраев. На узком
# или подтормаживающем канале часть тарболлов при этом стабильно отваливается по
# ETIMEDOUT и валит всю установку. Сокращаем параллелизм и даём внятный retry —
# на быстром канале это стоит считанных секунд.
ENV npm_config_maxsockets=3 \
    npm_config_fetch_retries=5 \
    npm_config_fetch_retry_mintimeout=20000 \
    npm_config_fetch_retry_maxtimeout=120000 \
    npm_config_fetch_timeout=600000

WORKDIR /app

COPY package.json /app/package.json
RUN npm install

COPY . /app

CMD ["npm", "run", "dev"]
