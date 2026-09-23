# TrustTunnel + WARP installer

Интерактивный установщик TrustTunnel endpoint для Ubuntu/Debian VPS.

Скрипт можно запускать на чистом сервере и повторно на уже настроенном сервере. Для аккуратной переустановки есть backup/restore identity: сертификат, ключи и клиенты можно сохранить, чтобы на телефоне или ПК потом ничего не менять.

## Что настраивает

- TrustTunnel на выбранном TCP-порту, по умолчанию `443`;
- актуальную версию TrustTunnel из latest GitHub release;
- обновление системы перед установкой;
- self-signed сертификат или Let's Encrypt на выбор;
- автообновление Let's Encrypt сертификата через systemd timer;
- HTTP/2 и опционально QUIC/HTTP3;
- WARP через `wireproxy`/SOCKS5, чтобы сайты видели WARP/Cloudflare IP, а не IP VPS;
- direct-режим без WARP;
- cascade SOCKS5 upstream;
- клиентов `client01`, `client02` и т.д.;
- TOML-файлы клиентов, ссылки и QR через веб-панель;
- ZIP-архив с клиентскими конфигами;
- UFW firewall;
- fail2ban для защиты SSH;
- BBR congestion control для TCP;
- systemd автоперезапуск сервисов при падении;
- короткую команду меню `ttmenu`.

При смене SSH-порта скрипт сначала проверяет конфигурацию `sshd`, затем меняет firewall. Старый SSH-порт сразу не закрывается, чтобы снизить риск потерять доступ к серверу.

## Быстрый запуск на VPS

Зайди на сервер по SSH и выполни:

```bash
curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh
```

После запуска появится начальное меню:

```text
1) Установить или переустановить TrustTunnel
2) Удалить TrustTunnel и WARP
3) Установить или переустановить только WARP
4) Удалить только WARP и переключить TrustTunnel на direct
5) Показать статус
6) Обновить только TrustTunnel endpoint
7) Проверить WARP
8) Включить WARP
9) Отключить WARP без удаления
10) Полностью перерегистрировать WARP-аккаунт
11) Создать backup identity (сертификат и клиенты)
12) Восстановить identity из backup
13) Обновить сертификат вручную
14) Сменить режим сертификата (Let's Encrypt / self-signed)
15) Speedtest
16) Настроить cascade SOCKS5 upstream
17) Установить или обновить веб-панель
18) Удалить веб-панель
19) Routing / access rules
20) Смена портов
21) Управление fail2ban
22) Управление UFW
23) Настроить доступ к веб-панели (localhost / HTTPS)
24) Включить / выключить веб-панель и сменить вход
25) Управление клиентами и tt:// ссылками
26) DNS, TLS profile, AntiDPI и post-quantum для TOML
27) Система, диагностика и журнал
0) Выход
```

Для обычной установки выбирай `1`.
Для обновления TrustTunnel без пересоздания клиентов выбирай `6`.
Для ручного обновления сертификата выбирай `13`.
Для переключения между `Let's Encrypt` и `self-signed` выбирай `14`.
Для веб-панели выбирай `17`.
Пункт `25` управляет клиентами из терминала: добавление, удаление, смена пароля, пересборка TOML/ZIP и `tt://` ссылка.
Пункт `26` хранит DNS, TLS profile, AntiDPI и post-quantum TLS для экспортируемых TOML. Изменение этих значений само по себе не трогает действующие файлы, пока отдельно не выбрано применение к TOML.
Пункт `27` содержит мониторинг, диагностику, логи, обновление пакетов, ежедневную проверку сервисов и тестовую настройку Telegram.

После установки главное меню можно открыть командой:

```bash
ttmenu
```

Старое имя тоже работает:

```bash
trusttunnel-menu
```

## Веб-панель

Веб-панель ставится через пункт `17` меню. Скрипт спросит порт панели и режим доступа:

- `localhost` - панель доступна только на `127.0.0.1` сервера, наружу порт не открывается. Это самый безопасный режим.
- `HTTPS` - панель доступна публично на выбранном порту, порт открывается в UFW. Используется текущий сертификат TrustTunnel.

Для режима `localhost` подключайся через SSH-туннель:

```bash
ssh -L 8088:127.0.0.1:8088 -p 49222 root@SERVER_IP
```

Потом открой в браузере:

```text
http://127.0.0.1:8088
```

В панели доступны только функции, которые реально применимы к этой установке:

- статус TrustTunnel/WARP/fail2ban/UFW;
- перезапуск TrustTunnel;
- переключение `direct` / `WARP via SOCKS` / `cascade SOCKS5`;
- speedtest;
- добавление, удаление клиентов и смена пароля конкретному клиенту;
- скачивание TOML, генерация QR и ссылок;
- смена порта TrustTunnel;
- управление доступом к самой панели: localhost/HTTPS и порт;
- простые routing/access rules через `rules.toml`;
- управление fail2ban;
- управление UFW.

Интерфейс панели построен как рабочая VPN-консоль с отдельными разделами:

- «Обзор» с сервисами, маршрутом, сертификатом, мониторингом ресурсов и быстрыми действиями;
- «Endpoint» с обновлением и защищённой переустановкой TrustTunnel;
- «Клиенты» с TOML HTTP/2 и HTTP/3, QR, `tt://` deep link, сменой пароля и удалением;
- «WARP», «Маршрутизация», «DNS и AntiDPI», «Сертификаты», «Безопасность», «Система» и «Панель».

Интерфейс панели построен как рабочая административная консоль: разделы сгруппированы по задачам, `Ctrl+K` открывает быстрый переход, а в таблице клиентов пароли скрыты до открытия карточки нужного клиента. Команды, которые меняют серверную конфигурацию, имеют соответствующий сценарий в `ttmenu`; панель не добавляет неподдерживаемые TrustTunnel функции, такие как фиктивные лимиты трафика, HWID или учёт «онлайн» без достоверных данных endpoint.

DNS, AntiDPI и post-quantum TLS по умолчанию выключены. Их сохранение пересобирает экспортируемые TOML-файлы, но не изменяет сертификат, логины или пароли. Сначала проверь новый TOML на одном устройстве.

Пароль панели создается автоматически при установке и выводится в конце. Посмотреть текущие данные, включить/выключить панель или сменить логин и пароль можно через `ttmenu` -> пункт `24`. В самой панели смена логина и пароля находится в разделе «Доступ к панели». Ручной вариант:

```bash
systemctl restart trusttunnel-panel
```

## Сертификаты

Скрипт умеет два режима:

- `self-signed` - проще и надежнее для ручного TOML/импорта. Клиенту нужен `server-cert.pem`. Автообновление не требуется.
- `Let's Encrypt` - публичный доверенный сертификат для домена. Нужен корректный DNS A/AAAA на VPS. Скрипт ставит systemd timer для обновления. На время обновления порт `80/tcp` открывается, после обновления закрывается.

Ручное обновление сертификата: пункт `13`.
Смена режима сертификата: пункт `14`.

## Запуск с Windows PowerShell

```powershell
ssh -t -p 22 root@SERVER_IP "curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh"
```

Если SSH-порт нестандартный:

```powershell
ssh -t -p 49222 root@SERVER_IP "curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/Dmitry1244/trusttunnel-auto-installer/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh"
```

## Что спросит скрипт

- домен TrustTunnel;
- email для Let's Encrypt, если выбран этот режим;
- количество клиентов;
- порт TrustTunnel для клиентов, по умолчанию `443`;
- менять ли SSH-порт;
- новый SSH-порт, по умолчанию `49222`;
- обновлять ли систему перед установкой;
- включать ли WARP;
- включать ли QUIC/HTTP3;
- включать ли fail2ban;
- подтверждение сброса UFW firewall.

В конце скрипт выводит короткую инструкцию для мобильного клиента: какой TOML импортировать, какой адрес/порт вводить вручную, где лежит `server-cert.pem` и где смотреть логины/пароли.

По умолчанию используется `TT_VERSION=latest`. Если нужно поставить конкретную версию:

```bash
TT_VERSION=v1.0.33 bash /tmp/install-trusttunnel-warp.sh
```

## Где будут клиенты

После установки на сервере:

```text
/root/trusttunnel-clients/
/root/trusttunnel-clients-YOUR_DOMAIN.zip
```

Если QUIC/HTTP3 включен, для каждого клиента будут два TOML-файла:

```text
client01-http2.toml
client01-http3.toml
```

В приложении также можно выбрать протокол вручную: HTTP/2 или QUIC/HTTP3.

Скачать ZIP на Windows:

```powershell
scp -P 22 root@SERVER_IP:/root/trusttunnel-clients-YOUR_DOMAIN.zip .
```

## Проверка

На сервере:

```bash
trusttunnel-status
```

Нормально, если:

- `trusttunnel` active;
- `warp-wireproxy` active, если WARP включен;
- `fail2ban` active, если fail2ban включен;
- выбранный TCP-порт TrustTunnel слушается;
- выбранный UDP-порт слушается, если включен QUIC/HTTP3;
- WARP public IP отличается от IP VPS;
- `net.ipv4.tcp_congestion_control = bbr`;
- systemd service использует `Restart=always`.

## Важно

- Скрипт может запускаться повторно, но перед рискованными действиями лучше создать backup identity пунктом `11`.
- Скрипт может сбрасывать UFW firewall при установке или пересборке правил.
- Открываются только SSH-порт и выбранный TCP-порт TrustTunnel.
- Если включен QUIC/HTTP3, дополнительно открывается UDP на выбранном порту TrustTunnel.
- Самый стабильный режим клиента: HTTP/2.
- Если нужен WARP IP на сайтах, используй HTTP/2.
- QUIC/HTTP3 сейчас следует считать экспериментальным режимом.
- В связке `TrustTunnel -> WARP via SOCKS (wireproxy)` полноценный UDP outbound не гарантируется, поэтому QUIC/HTTP3 может подключаться, но не давать нормальный интернет.
- При self-signed сертификате клиентам нужен общий `server-cert.pem`.

## Identity backup

Скрипт умеет сохранить и восстановить identity сервера без смены настроек на клиентах.

Что сохраняется:

- `cert.pem`;
- `key.pem`;
- `credentials.toml`;
- `hosts.toml`;
- клиентские TOML и `clients-credentials.txt`.

Меню:

- `11` - создать backup identity;
- `12` - восстановить identity из backup.

После backup на сервере появятся:

```text
/root/trusttunnel-identity-backup
/root/YOUR_DOMAIN-identity-backup.tar.gz
```
## Мониторинг и обслуживание

Веб-панель показывает состояние TrustTunnel, WARP, CPU/RAM, диск, uptime и суммарный трафик сетевых интерфейсов VPS. Также доступны диагностика DNS/портов/сертификата, журналы TrustTunnel, создание и скачивание ZIP-backup identity, перезапуск WARP, ручное продление Let's Encrypt, планировщик ежедневной проверки и настройка Telegram для тестового уведомления.

Статистика трафика по отдельному пользователю и список онлайн-пользователей не показываются, пока TrustTunnel endpoint не предоставляет достоверные события сессий.
