# TrustTunnel + WARP installer

Интерактивный установщик TrustTunnel endpoint для Ubuntu/Debian VPS.

Что настраивает:

- TrustTunnel на выбранном TCP-порту, по умолчанию `443`;
- актуальную версию TrustTunnel из latest GitHub release;
- обновление системы перед установкой;
- WARP через `wireproxy`, чтобы сайты видели WARP/Cloudflare IP, а не IP VPS;
- HTTP/2 и опционально QUIC/HTTP3;
- выбор порта TrustTunnel, по умолчанию `443`;
- клиентов `client01`, `client02` и т.д.;
- TOML-файлы клиентов;
- ZIP-архив с клиентскими конфигами;
- UFW firewall;
- fail2ban для защиты SSH;
- BBR congestion control для TCP.

При смене SSH-порта скрипт сначала проверяет конфигурацию `sshd`, затем меняет firewall. Это снижает риск потерять доступ к серверу.

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
0) Выход
```

Для обычной установки выбирай `1`.
Для обновления TrustTunnel без пересоздания клиентов выбирай `6`.

После установки главное меню можно открыть командой:

```bash
trusttunnel-menu
```

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
- `warp-wireproxy` active;
- `fail2ban` active;
- выбранный TCP-порт TrustTunnel слушается;
- выбранный UDP-порт слушается, если включен QUIC/HTTP3;
- WARP public IP отличается от IP VPS.
- `net.ipv4.tcp_congestion_control = bbr`.
- systemd service использует `Restart=always`.

## Важно

- Скрипт рассчитан на чистый Ubuntu/Debian VPS.
- Скрипт сбрасывает UFW firewall.
- Открываются только SSH-порт и выбранный TCP-порт TrustTunnel.
- Если включен QUIC/HTTP3, дополнительно открывается UDP на выбранном порту TrustTunnel.
- Самый стабильный режим клиента: HTTP/2.
- Сертификат self-signed, но он встроен в TOML-файлы клиентов.
