# AIVPN

Обычные VPN давно мертвы. Провайдеры и GFW (китайский файрвол) палят WireGuard и OpenVPN за доли секунды по размерам пакетов, интервалам и хэндшейкам. Можете шифровать трафик хоть тройным AES — DPI-системам плевать на содержимое, они блокируют саму *форму* соединения.

**AIVPN** — это мой ответ современным системам глубокого анализа трафика (DPI). Мы не просто шифруем пакеты, мы "натягиваем" на них маску реальных приложений. Для провайдера вы сидите в Zoom-колле или листаете TikTok, а на деле — это зашифрованный туннель.

Чтобы проверить это на практике, я разработал собственный эмулятор DPI, воспроизводил реальные сценарии фильтрации и целенаправленно блокировал трафик в разных режимах. Затем прогонял систему под высокой нагрузкой, чтобы оценить устойчивость, скорость переключения масок и стабильность маршрутизации. Для быстрого роутинга внедрено мое запатентованное решение: заявка USPTO (USA) № 19/452,440 от Jan 19, 2026 — *SYSTEM AND METHOD FOR UNSUPERVISED MULTI-TASK ROUTING VIA SIGNAL RECONSTRUCTION RESONANCE*.


## Поддерживаемые платформы

| Платформа | Сервер | Клиент | Полный туннель | Примечания |
|-----------|--------|--------|----------------|------------|
| **Linux** | ✅ | ✅ | ✅ | Основная платформа, TUN через `/dev/net/tun` |
| **macOS** | — | ✅ | ✅ | Через `utun`, автоматическая настройка маршрутов |
| **Windows** | — | ✅ | ✅ | Через [Wintun](https://www.wintun.net/) драйвер |
| **Android** | — | ✅ | ✅ | Kotlin-приложение через `VpnService` API |

### Текущий статус клиентов

- ✅ Приложение macOS: работает
- ✅ CLI-клиент: работает
- ✅ Android-приложение: работает
- 🧪 Windows-клиент: сейчас в тестировании

## 📥 Готовые бинарники

Не нужно ничего компилировать — скачайте и запускайте:

| Платформа | Файл | Размер | Примечания |
|-----------|------|--------|------------|
| **macOS** | [aivpn-macos.dmg](releases/aivpn-macos.dmg) | ~1.8 МБ | Приложение в menu bar с интерфейсом RU/EN |
| **Linux** | [aivpn-client-linux-x86_64](releases/aivpn-client-linux-x86_64) | ~4.0 МБ | Нативный x86_64 GNU/Linux CLI бинарник |
| **Linux ARMv7** | [aivpn-client-linux-armv7-musleabihf](releases/aivpn-client-linux-armv7-musleabihf) | ~4-5 МБ | Статический musl CLI-клиент для ARMv7 серверов и SBC |
| **Entware / MIPSel** | [aivpn-client-linux-mipsel-musl](releases/aivpn-client-linux-mipsel-musl) | ~4-5 МБ | Статический musl CLI-клиент для роутеров с Entware |
| **Windows** | [aivpn-windows-package.zip](releases/aivpn-windows-package.zip) | ~7 МБ | Внутри `aivpn-client.exe` и `wintun.dll` |
| **Android** | [aivpn-client.apk](releases/aivpn-client.apk) | ~6.5 МБ | Установите и вставьте ключ подключения |
| **Linux Server** | [aivpn-server-linux-x86_64](releases/aivpn-server-linux-x86_64) | ~4.0 МБ | Готовый x86_64 GNU/Linux бинарник сервера для VPS или быстрого Docker-деплоя |
| **Linux Server ARMv7** | [aivpn-server-linux-armv7-musleabihf](releases/aivpn-server-linux-armv7-musleabihf) | ~4-5 МБ | Статический musl бинарник сервера для ARMv7 Linux-хостов |
| **Linux Server MIPSel** | [aivpn-server-linux-mipsel-musl](releases/aivpn-server-linux-mipsel-musl) | ~4-5 МБ | Статический musl бинарник сервера для лёгких MIPSel/Entware систем |


### Быстрый старт (macOS)
1. Скачайте и откройте `aivpn-macos.dmg`
2. Перетащите **Aivpn.app** в Applications
3. Запустите — приложение появится в menu bar (без иконки в Dock)
4. Вставьте ключ подключения (`aivpn://...`) и нажмите **Подключить**
5. Нажмите 🇷🇺/🇬🇧 для переключения языка
> ⚠️ VPN-клиенту требуются права root для создания TUN-устройства. Приложение запросит пароль через `sudo`.

### Быстрый старт (Windows)
1. Скачайте и распакуйте [aivpn-windows-package.zip](releases/aivpn-windows-package.zip)
2. Убедитесь, что `aivpn-client.exe` и `wintun.dll` лежат в одной папке
3. Запустите **от имени администратора** в PowerShell:
   ```powershell
   .\aivpn-client.exe -k "ваш_ключ_подключения"
   ```

### Быстрый старт (Linux)
1. Скачайте [aivpn-client-linux-x86_64](releases/aivpn-client-linux-x86_64)
2. Сделайте файл исполняемым и запустите от root:
    ```bash
    chmod +x ./aivpn-client-linux-x86_64
    sudo ./aivpn-client-linux-x86_64 -k "ваш_ключ_подключения"
    ```

### Быстрый старт (Entware роутеры)
1. Скачайте [aivpn-client-linux-mipsel-musl](releases/aivpn-client-linux-mipsel-musl) для MIPSel роутеров или [aivpn-client-linux-armv7-musleabihf](releases/aivpn-client-linux-armv7-musleabihf) для ARMv7 роутеров.
2. Скопируйте бинарник на роутер, например в `/opt/bin/aivpn-client`.
3. Сделайте файл исполняемым и запустите из Entware shell от root:
    ```sh
    chmod +x /opt/bin/aivpn-client
    /opt/bin/aivpn-client -k "ваш_ключ_подключения"
    ```
4. Эти musl-сборки статически слинкованы, поэтому на роутере не нужен Rust toolchain и дополнительные shared libraries.

### Быстрый старт (Android)
1. Скачайте и установите `aivpn-client.apk`
2. Вставьте ключ подключения (`aivpn://...`) в приложение
3. Нажмите **Подключить**

## ❤️ Поддержать проект

Если проект оказался полезным, вы можете поддержать его развитие донейшеном через Tribute:

👉 https://t.me/tribute/app?startapp=dzX1

Любая поддержка помогает развивать AIVPN дальше. Спасибо! 🙌

## Главная фича: Нейронный Резонанс (AI)

Самое интересное под капотом — это наш ИИ-модуль, который мы называем **Neural Resonance**.
Мы не стали тащить в проект огромные LLM-модели на 400 мегабайт, которые сожрут всю память на дешевом VPS. Вместо этого:

- **Baked Mask Encoder:** Под каждую маску (кодек WebRTC, протокол QUIC) мы натренировали и "запекли" в бинарник микро-нейросеть (MLP 64→128→64). Она весит всего ~66 КБ!
- **Анализ в реальном времени:** Эта нейронка на лету анализирует энтропию и IAT (тайминги) прилетающих UDP-пакетов.
- **Охота на цензоров:** Если DPI-система провайдера пытается прощупать наш сервер (Active Probing) или начинает задерживать пакеты, нейромодуль видит рост ошибки реконструкции (MSE).
- **Авто-ротация масок:** Как только ИИ понимает, что текущая маска скомпрометирована (например, `webrtc_zoom` спалили), сервер и клиент *без разрыва соединения* перестраивают шейпинг трафика под резервную маску (например, на `dns_over_udp`). Никаких дисконнектов!

## Что ещё крутого

- **Zero-RTT и PFS:** Нет классического рукопожатия (handshake), которое так любят ловить снифферы. Данные льются с первого же пакета. При этом работает Perfect Forward Secrecy — ключи ротируются на лету, так что если сервак когда-нибудь изымут, расшифровать старый дамп трафика не выйдет.
- **O(1) криптотеги сессий:** Мы не передаем ID сессии в открытом виде. Вместо этого в каждый пакет вшивается динамический криптографический тег, зависящий от таймстемпа и секретного ключа. Сервер находит нужного клиента моментально, а для стороннего наблюдателя это просто белый шум.
- **Написан на Rust:** Быстрый, безопасный, без утечек памяти. Весь бинарник клиента весит около 2.5 МБ. Спокойно крутится на серверах за пару баксов.

## Как поднять всё это добро

### 1. Клонируем репозиторий

```bash
git clone https://github.com/infosave2007/aivpn.git
cd aivpn
```

### 2. Сборка (потребуется Rust 1.75+)

Проект разбит на воркспейсы: `aivpn-common` (шифры и маски), `aivpn-server` и `aivpn-client`.

```bash
# Все плафтормы — одна команда:
cargo build --release
```

Чтобы обновить Linux-артефакт сервера без установки Rust на хост:

```bash
./build-server-release.sh
```

Для статических musl-сборок под ARMv7 серверы и MIPSel/Entware роутеры:

```bash
./build-musl-release.sh server armv7-unknown-linux-musleabihf
./build-musl-release.sh server mipsel-unknown-linux-musl
./build-musl-release.sh client armv7-unknown-linux-musleabihf
./build-musl-release.sh client mipsel-unknown-linux-musl
```

Чтобы развернуть последнюю опубликованную Linux-версию сервера на VPS одной командой:

```bash
./deploy-server-release.sh
```

> Для GitHub Releases серверным Linux-артефактом по умолчанию должен оставаться `aivpn-server-linux-x86_64`, основным Windows-артефактом — `aivpn-windows-package.zip`, а для ARM/Entware нужно прикладывать musl-артефакты `aivpn-server-linux-armv7-musleabihf`, `aivpn-server-linux-mipsel-musl`, `aivpn-client-linux-armv7-musleabihf` и `aivpn-client-linux-mipsel-musl`. Отдельный `aivpn-client.exe` безопасно выкладывать только вместе с `wintun.dll` рядом.

Автоматизация GitHub Releases: workflow в `.github/workflows/server-release-asset.yml` собирает `aivpn-server-linux-x86_64`, а также ARMv7 и MIPSel musl-артефакты для сервера и клиента при публикации Release и автоматически прикладывает их к релизу.

Для Docker-backed кросс-сборки без локального тулчейна используйте:

```bash
./build-musl-release.sh client armv7-unknown-linux-musleabihf
./build-musl-release.sh client mipsel-unknown-linux-musl
./build-musl-release.sh server armv7-unknown-linux-musleabihf
./build-musl-release.sh server mipsel-unknown-linux-musl
```

Эти артефакты рассчитаны на ARM Linux-серверы/SBC и MIPSel-роутеры с Entware.

### 3. Сервер (только Linux)

#### Вариант А: Docker (рекомендуется)

Самый простой способ — всё настроено в `docker-compose.yml`.

```bash
# Определяем Compose-команду, которая есть именно на вашей системе
if docker compose version >/dev/null 2>&1; then
    AIVPN_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    AIVPN_COMPOSE="docker-compose"
else
    echo "Установите Docker Compose v2 (`docker-compose-v2` или `docker-compose-plugin`) либо legacy `docker-compose`."
    exit 1
fi

# Генерируем ключ сервера
mkdir -p config
openssl rand 32 > config/server.key
chmod 600 config/server.key

# Включаем NAT (нужен для доступа в интернет через VPN)
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE

# Быстрый старт из готового Linux-бинарника
AIVPN_SERVER_DOCKERFILE=Dockerfile.prebuilt $AIVPN_COMPOSE up -d aivpn-server

# Или оставить исходный путь со сборкой из исходников
$AIVPN_COMPOSE up -d aivpn-server
```

Быстрый путь ожидает локальный файл `releases/aivpn-server-linux-x86_64`. Его можно собрать командой `./build-server-release.sh` или скачать из Releases перед запуском Docker.

Для быстрого деплоя на VPS одной командой используйте `./deploy-server-release.sh`. Скрипт скачивает релизный артефакт, создаёт `config/server.key` при необходимости, включает IPv4 forwarding, добавляет NAT-правило для интерфейса по умолчанию и запускает Docker через `Dockerfile.prebuilt`.

Если у вас включён firewall, откройте `443/udp` тем инструментом, который есть в системе:

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 443/udp

# firewalld (RHEL/CentOS/Fedora)
sudo firewall-cmd --add-port=443/udp --permanent
sudo firewall-cmd --reload
```

> Контейнер запускается с `network_mode: "host"` и монтирует `./config` → `/etc/aivpn` внутри контейнера.

#### Вариант Б: На голом железе

Заходите на свой VPS, генерите ключ:

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
```

Поднимаем:

```bash
sudo ./target/release/aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

Включаем NAT:

```bash
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$DEFAULT_IFACE" -j MASQUERADE
```

### 3.1 Управление клиентами

AIVPN использует модель регистрации клиентов по аналогии с WireGuard/XRay: у каждого клиента — уникальный PSK, статический VPN IP и статистика трафика.

Вся конфигурация упаковывается в один **ключ подключения** — одну строку, которую пользователь вставляет в приложение или CLI-клиент.

#### Docker

```bash
# Используйте ту же Compose-команду, что определили выше
# Добавить клиента (выводит ключ подключения)
$AIVPN_COMPOSE exec aivpn-server aivpn-server \
    --add-client "Телефон Алисы" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443

# Вывод:
# ✅ Client 'Телефон Алисы' created!
#    ID:     a1b2c3d4e5f67890
#    VPN IP: 10.0.0.2
#
# ══ Connection Key (paste into app) ══
#
# aivpn://eyJpIjoiMTAuMC4wLjIiLCJrIjoiLi4uIiwicCI6Ii4uLiIsInMiOiIxLjIuMy40OjQ0MyJ9

# Список всех клиентов со статистикой
docker compose exec aivpn-server aivpn-server \
    --list-clients --clients-db /etc/aivpn/clients.json

# Показать конкретного клиента (и его ключ подключения)
$AIVPN_COMPOSE exec aivpn-server aivpn-server \
    --show-client "Телефон Алисы" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443

# Удалить клиента
docker compose exec aivpn-server aivpn-server \
    --remove-client "Телефон Алисы" \
    --clients-db /etc/aivpn/clients.json
```

> Используется имя сервиса Compose, поэтому команда не зависит от сгенерированного имени контейнера.

#### На голом железе

```bash
# Добавить клиента
aivpn-server \
    --add-client "Телефон Алисы" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443

# Список всех клиентов со статистикой
aivpn-server --list-clients --clients-db /etc/aivpn/clients.json

# Показать конкретного клиента (и его ключ подключения)
aivpn-server \
    --show-client "Телефон Алисы" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443

# Удалить клиента
aivpn-server \
    --remove-client "Телефон Алисы" \
    --clients-db /etc/aivpn/clients.json
```

### 4. Клиент

#### Ключ подключения (рекомендуется)

Самый простой способ — вставить ключ подключения из `--add-client`:

```bash
sudo ./target/release/aivpn-client -k "aivpn://eyJp..."
```

Полный туннель:

```bash
sudo ./target/release/aivpn-client -k "aivpn://eyJp..." --full-tunnel
```

#### Ручной режим

Также можно указать адрес и ключ сервера вручную (без PSK — для работы без регистрации):

#### Linux

```bash
sudo ./target/release/aivpn-client \
    --server IP_ВАШЕГО_VPS:443 \
    --server-key ПУБЛИЧНЫЙ_КЛЮЧ_BASE64
```

Для полного туннеля (весь трафик через VPN):

```bash
sudo ./target/release/aivpn-client \
    --server IP_ВАШЕГО_VPS:443 \
    --server-key ПУБЛИЧНЫЙ_КЛЮЧ_BASE64 \
    --full-tunnel
```

#### macOS

Точно так же, `cargo build --release` соберет нативный бинарник:

```bash
sudo ./target/release/aivpn-client \
    --server IP_ВАШЕГО_VPS:443 \
    --server-key ПУБЛИЧНЫЙ_КЛЮЧ_BASE64
```

> macOS автоматически настроит `utun`-интерфейс и маршруты через `ifconfig` / `route`.

#### Windows

Для пользователей предпочтительно скачивать и распаковывать `releases/aivpn-windows-package.zip`.

Если выкладываете файлы по отдельности, `wintun.dll` (от [WireGuard/wintun](https://www.wintun.net/)) должен лежать рядом с `.exe`:

```
aivpn-client.exe
wintun.dll
```

Запуск из Powershell **с правами администратора**:

```powershell
.\aivpn-client.exe --server IP_ВАШЕГО_VPS:443 --server-key ПУБЛИЧНЫЙ_КЛЮЧ_BASE64
```

Для полного туннеля:

```powershell
.\aivpn-client.exe --server IP_ВАШЕГО_VPS:443 --server-key ПУБЛИЧНЫЙ_КЛЮЧ_BASE64 --full-tunnel
```

> Клиент автоматически настроит маршруты через `route add` и корректно откатит их при завершении.

### 5. Android

1. Установите APK (`aivpn-android/app/build/outputs/apk/debug/app-debug.apk`)
2. Вставьте свой **ключ подключения** (`aivpn://...`) в поле ввода
3. Нажмите **Подключить**

Ключ подключения содержит всё: адрес сервера, публичный ключ, ваш PSK и VPN IP. Никакой ручной настройки.

## Кросс-компиляция

Можно собирать клиент под любую платформу прямо со своей машины:

```bash
# Для Linux из macOS/Windows
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# Для Windows из Linux/macOS
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

Для статических musl-кросс-сборок без локального тулчейна используйте Docker-backed release builds:

```bash
./build-musl-release.sh client armv7-unknown-linux-musleabihf
./build-musl-release.sh client mipsel-unknown-linux-musl
./build-musl-release.sh server armv7-unknown-linux-musleabihf
./build-musl-release.sh server mipsel-unknown-linux-musl
```

Эти артефакты рассчитаны на ARM Linux-серверы/SBC и MIPSel-роутеры с Entware.

Для Entware-роутеров обычный поток такой: собрать или скачать musl-артефакт, скопировать его в `/opt/bin`, выдать `chmod +x` и запускать прямо из shell роутера.

## Структура проекта

```
aivpn/
├── aivpn-common/src/
│   ├── crypto.rs        # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs          # Профили мимикрии (WebRTC, QUIC, DNS)
│   └── protocol.rs      # Формат пакетов, inner types
├── aivpn-client/src/
│   ├── client.rs        # Основная логика клиента
│   ├── tunnel.rs        # TUN-интерфейс (Linux / macOS / Windows)
│   └── mimicry.rs       # Движок шейпинга трафика
├── aivpn-server/src/
│   ├── gateway.rs       # UDP-шлюз, MaskCatalog, resonance loop
│   ├── neural.rs        # Baked Mask Encoder, AnomalyDetector
│   ├── nat.rs           # NAT-форвардер (iptables)
│   ├── client_db.rs     # База клиентов (PSK, статический IP, статистика)
│   ├── key_rotation.rs  # Ротация сессионных ключей
│   └── metrics.rs       # Prometheus-мониторинг
├── aivpn-android/       # Android-клиент (Kotlin)
├── Dockerfile
├── docker-compose.yml
└── build.sh
```

## Разработка и контрибы

Хотите поковыряться в коде или обучить свою маску для нейронки? Залетайте:

- Движок масок: [`aivpn-common/src/mask.rs`](aivpn-common/src/mask.rs)
- Обученные веса и детектор аномалий: [`aivpn-server/src/neural.rs`](aivpn-server/src/neural.rs)
- Кроссплатформенный TUN-модуль: [`aivpn-client/src/tunnel.rs`](aivpn-client/src/tunnel.rs)
- Тесты (больше сотни): `cargo test`

Буду рад пулл-реквестам! Особо ищем спецов по анализу трафика, чтобы снимать дампы с реальных приложений и обучать новые профили для Neural Resonance.

---

Лицензия — MIT. Пользуйтесь, форкайте, обходите блокировки с умом.
