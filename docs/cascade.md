# Каскад: вход в России, выход за границей

```
клиент ──AmneziaWG (UDP 51820)──▶ RU-сервер ──VLESS+XHTTP+TLS (443)──▶ выход ──▶ интернет
                                     │
                                     └── российские сайты и IP выходят напрямую с RU-адреса
```

Клиенты подключаются к российскому серверу по прежним ключам: ключи, параметры
обфускации и домен не меняются. Внутри контейнера трафик с `awg0` перехватывается
через TPROXY и разбирается Xray: российские домены (`geosite:category-ru`) и адреса
(`geoip:ru`) уходят напрямую, остальное идёт по туннелю на выход. DNS клиентов
(1.1.1.1) отвечает встроенный DoH-резолвер Xray через туннель, QUIC (UDP/443)
блокируется, чтобы браузеры использовали TCP.

## Выход (сервер за границей)

Ничего, кроме Xray и, при желании, Cloudflare Tunnel:

1. Xray (официальный скрипт `XTLS/Xray-install`), inbound VLESS + XHTTP без TLS
   на `127.0.0.1:2053`, режим `packet-up`, свой `path` и `uuid`.
2. Вариант A, за Cloudflare: `cloudflared service install <token>`, в туннеле
   Public Hostname `go.<домен>` → `http://127.0.0.1:2053`. IP выхода снаружи не
   виден и его блокировка ни на что не влияет.
   Вариант B, напрямую: TLS-терминатор (Caddy/nginx) на 443 с сертификатом,
   проксирующий на `127.0.0.1:2053`.

## Вход (RU-сервер)

В `.env` добавить:

```env
CASCADE_ENABLED=1
EXIT_HOST=go.example.com
EXIT_PORT=443
EXIT_SNI=go.example.com
EXIT_UUID=<uuid из inbound выхода>
EXIT_PATH=/<path из inbound выхода>
CASCADE_RU_DIRECT=1
CASCADE_BLOCK_QUIC=1
```

Дальше обычный `docker compose up -d --build`. Без `CASCADE_ENABLED=1` контейнер
работает как раньше.

## Проверка

```bash
# туннель и роутинг, изнутри контейнера
docker exec amnezia-vpn curl -s --socks5-hostname 127.0.0.1:1081 https://ifconfig.me                 # IP выхода
docker exec amnezia-vpn curl -s --socks5-hostname 127.0.0.1:1081 https://yandex.ru/internet/api/v0/ip # IP RU-сервера
# правила TPROXY
docker exec amnezia-vpn iptables -t mangle -S XRAY
# логи Xray попадают в логи контейнера
docker compose logs -f | grep -i xray
```

## Ограничения

- Cloudflare закрывает HTTP-потоки без данных дольше 100 с; XHTTP переустанавливает
  сессию сам, но долгие простаивающие TCP-соединения могут оборваться.
- QUIC заблокирован намеренно.
- IPv6 внутри туннеля не маршрутизируется (как и раньше), клиенты откатываются на IPv4.
- Cloudflare видит метаданные и DNS-запросы, содержимое HTTPS-сайтов остаётся
  зашифрованным.
