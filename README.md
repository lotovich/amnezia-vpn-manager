# AmneziaWG VPN Manager

Telegram-бот для управления личным VPN-сервером на базе **AmneziaWG** (WireGuard с защитой от DPI).

## Особенности

- **Защита от блокировок**: AmneziaWG обфусцирует трафик WireGuard
- **Миграция без боли**: Клиенты используют домен, а не IP — при смене сервера достаточно обновить DNS
- **Управление через Telegram**: Создание клиентов, QR-коды, статистика
- **Визуализация трафика**: Графики потребления для каждого клиента
- **Docker-ready**: Один контейнер, одна команда для запуска

---

## Быстрый старт

### Шаг 1: Аренда VPS

Подойдёт любой VPS с:
- **ОС**: Ubuntu 22.04 / Debian 12 (рекомендуется)
- **RAM**: 512 MB минимум
- **CPU**: 1 vCPU
- **Виртуализация**: KVM или любая (благодаря userspace-реализации)

Рекомендуемые провайдеры:
- [Hetzner](https://hetzner.cloud) (Германия/Финляндия)
- [DigitalOcean](https://digitalocean.com) (много локаций)
- [Vultr](https://vultr.com) (много локаций)

### Шаг 2: Установка Docker на VPS

```bash
# Подключаемся к серверу
ssh root@your-server-ip

# Устанавливаем Docker (официальный способ)
curl -fsSL https://get.docker.com | sh

# Устанавливаем Docker Compose
apt install docker-compose-plugin -y

# Проверяем
docker --version
docker compose version
```

### Шаг 3: Настройка домена

1. Купите домен (или используйте существующий)
2. Добавьте A-запись, указывающую на IP вашего VPS:
   ```
   vpn.yourdomain.com  →  123.45.67.89
   ```
3. Подождите 5-15 минут для распространения DNS

> **Важно**: Использование домена позволяет менять серверы без перенастройки клиентов!

### Шаг 4: Создание Telegram-бота

1. Откройте [@BotFather](https://t.me/BotFather) в Telegram
2. Отправьте `/newbot`
3. Следуйте инструкциям, получите **токен** вида:
   ```
   1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
   ```
4. Сохраните токен — он понадобится для `.env`

### Шаг 5: Узнайте свой Telegram ID

1. Откройте [@userinfobot](https://t.me/userinfobot) в Telegram
2. Отправьте `/start`
3. Бот ответит вашим ID (числовой, например `123456789`)
4. Повторите для всех администраторов

### Шаг 6: Генерация ключей сервера

**На VPS** выполните:

```bash
# Создаём временный контейнер для генерации ключей
docker run --rm -it golang:1.22-bookworm bash -c "
  git clone https://github.com/amnezia-vpn/amneziawg-tools.git && \
  cd amneziawg-tools/src && \
  make && \
  PRIVATE=\$(./wg genkey) && \
  PUBLIC=\$(echo \$PRIVATE | ./wg pubkey) && \
  echo '' && \
  echo '============================================' && \
  echo 'YOUR KEYS (save them!):' && \
  echo '============================================' && \
  echo \"SERVER_PRIVATE_KEY=\$PRIVATE\" && \
  echo \"SERVER_PUBLIC_KEY=\$PUBLIC\" && \
  echo '============================================'
"
```

**Сохраните оба ключа!** Приватный ключ — секрет, публичный нужен для клиентов.

### Шаг 7: Клонирование и настройка

```bash
# Клонируем репозиторий
cd /opt
git clone https://github.com/your-username/amnezia-vpn-manager.git vpn
cd vpn

# Или создаём вручную и копируем файлы
mkdir -p /opt/vpn
cd /opt/vpn
# ... скопируйте все файлы проекта ...

# Создаём .env из примера
cp .env.example .env

# Редактируем конфигурацию
nano .env
```

Заполните `.env`:

```env
BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
ADMIN_IDS=123456789,987654321
VPN_HOST=vpn.yourdomain.com
SERVER_PRIVATE_KEY=сгенерированный_приватный_ключ
SERVER_PUBLIC_KEY=сгенерированный_публичный_ключ
VPN_PORT=51820
```

### Шаг 8: Запуск

```bash
# Собираем и запускаем
docker compose up -d --build

# Проверяем логи
docker compose logs -f
```

Если всё хорошо, вы увидите:
```
[INFO] AmneziaWG VPN Manager starting...
[INFO] VPN Host: vpn.yourdomain.com
[INFO] AmneziaWG interface awg0 is up
[INFO] Bot started, waiting for commands...
```

### Шаг 9: Открытие порта

```bash
# Если используется ufw (Ubuntu)
ufw allow 51820/udp

# Если используется firewalld (CentOS/Fedora)
firewall-cmd --permanent --add-port=51820/udp
firewall-cmd --reload
```

---

## Использование бота

### Команды

| Команда | Описание |
|---------|----------|
| `/start` | Показать справку |
| `/create <имя>` | Создать нового клиента |
| `/delete <имя>` | Удалить клиента |
| `/list` | Список всех клиентов |
| `/stats` | Статистика трафика с графиком |

### Примеры

```
/create phone_john
/create laptop_mary
/stats
/delete phone_john
```

После `/create` бот пришлёт:
1. Файл `.conf` для импорта в AmneziaVPN
2. QR-код для сканирования телефоном

---

## Клиентские приложения

Для подключения используйте **AmneziaVPN** (не обычный WireGuard!):

- **Android**: [Google Play](https://play.google.com/store/apps/details?id=org.amnezia.vpn)
- **iOS**: [App Store](https://apps.apple.com/app/amneziavpn/id1600529900)
- **Windows/macOS/Linux**: [GitHub Releases](https://github.com/amnezia-vpn/amnezia-client/releases)

---

## Миграция на новый сервер

Главное преимущество системы — простая миграция:

### Что копировать

```bash
# На старом сервере
docker compose down
tar -czf vpn-backup.tar.gz .env docker-compose.yml

# Дополнительно экспортируем volumes
docker run --rm -v amnezia_vpn_data:/data -v $(pwd):/backup alpine \
  tar -czf /backup/data-backup.tar.gz /data
docker run --rm -v amnezia_vpn_config:/config -v $(pwd):/backup alpine \
  tar -czf /backup/config-backup.tar.gz /config
```

### На новом сервере

```bash
# Устанавливаем Docker (см. Шаг 2)
# Создаём директорию
mkdir -p /opt/vpn && cd /opt/vpn

# Копируем файлы с старого сервера
scp old-server:/opt/vpn/vpn-backup.tar.gz .
scp old-server:/opt/vpn/data-backup.tar.gz .
scp old-server:/opt/vpn/config-backup.tar.gz .

# Распаковываем
tar -xzf vpn-backup.tar.gz

# Восстанавливаем volumes
docker volume create amnezia_vpn_data
docker volume create amnezia_vpn_config
docker run --rm -v amnezia_vpn_data:/data -v $(pwd):/backup alpine \
  tar -xzf /backup/data-backup.tar.gz -C /
docker run --rm -v amnezia_vpn_config:/config -v $(pwd):/backup alpine \
  tar -xzf /backup/config-backup.tar.gz -C /

# Запускаем
docker compose up -d --build
```

### Обновляем DNS

Измените A-запись домена на новый IP сервера.

**Клиентам ничего менять не нужно!** После обновления DNS они автоматически подключатся к новому серверу.

---

## Структура проекта

```
.
├── docker-compose.yml    # Конфигурация Docker
├── Dockerfile            # Сборка контейнера
├── entrypoint.sh         # Скрипт запуска
├── requirements.txt      # Python-зависимости
├── .env.example          # Пример конфигурации
├── .env                  # Ваша конфигурация (не коммитить!)
└── src/
    ├── main.py           # Точка входа
    ├── bot_handlers.py   # Обработчики команд бота
    ├── vpn_manager.py    # Управление AmneziaWG
    ├── database.py       # Работа с SQLite
    └── stats_viz.py      # Генерация графиков
```

---

## Параметры обфускации

AmneziaWG использует параметры для маскировки трафика:

| Параметр | Описание | По умолчанию |
|----------|----------|--------------|
| `Jc` | Количество junk-пакетов | 4 |
| `Jmin` | Минимальный размер junk | 40 |
| `Jmax` | Максимальный размер junk | 70 |
| `S1` | Размер junk в init-пакете | 0 |
| `S2` | Размер junk в response-пакете | 0 |
| `H1-H4` | Magic-заголовки | 1, 2, 3, 4 |

Эти параметры **должны совпадать** на сервере и всех клиентах.

Если дефолтные значения начнут блокироваться, измените их в `.env`:

```env
AWG_Jc=8
AWG_Jmin=50
AWG_Jmax=100
AWG_H1=12345678
```

> **Важно**: После изменения параметров нужно пересоздать всех клиентов!

---

## Troubleshooting

### Бот не отвечает

1. Проверьте токен в `.env`
2. Проверьте, что ваш ID в `ADMIN_IDS`
3. Посмотрите логи: `docker compose logs -f`

### Клиент не подключается

1. Проверьте, что порт открыт: `nc -zvu your-domain 51820`
2. Проверьте DNS: `nslookup vpn.yourdomain.com`
3. Убедитесь, что используете AmneziaVPN, а не обычный WireGuard

### Нет интернета через VPN

1. Проверьте IP forwarding: `cat /proc/sys/net/ipv4/ip_forward` (должен быть `1`)
2. Проверьте iptables: `iptables -t nat -L POSTROUTING`
3. Проверьте интерфейс: `ip addr show awg0`

### Счётчики трафика не работают

Статистика собирается каждые 60 секунд. Подождите и проверьте:
```bash
docker compose exec amnezia-vpn awg show
```

---

## Безопасность

- **Никогда не коммитьте `.env`** — там ваши ключи
- Бот отвечает **только** пользователям из whitelist
- Rate limiting защищает от случайного спама
- Все команды логируются

---

## Лицензия

MIT

---

## Благодарности

- [AmneziaVPN](https://github.com/amnezia-vpn) — за протокол и клиенты
- [WireGuard](https://www.wireguard.com/) — за базовый протокол
- [aiogram](https://github.com/aiogram/aiogram) — за отличный фреймворк для ботов
