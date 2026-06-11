# TrustTunnel + WARP installer

Интерактивный установщик TrustTunnel endpoint для Ubuntu/Debian VPS.

Что настраивает:

- TrustTunnel на `443/tcp`;
- обновление системы перед установкой;
- WARP через `wireproxy`, чтобы сайты видели WARP/Cloudflare IP, а не IP VPS;
- HTTP/2 и опционально QUIC/HTTP3;
- клиентов `client01`, `client02` и т.д.;
- TOML-файлы клиентов;
- ZIP-архив с клиентскими конфигами;
- UFW firewall;
- fail2ban для защиты SSH;
- BBR congestion control для TCP.

## Быстрый запуск на VPS

Зайди на сервер по SSH и выполни:

```bash
curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh
```

Замени `GITHUB_USER/REPO_NAME` на свой GitHub-репозиторий.

После запуска появится начальное меню:

```text
1) Установить или переустановить TrustTunnel
2) Удалить TrustTunnel и WARP
3) Установить или переустановить только WARP
4) Удалить только WARP и переключить TrustTunnel на direct
5) Показать статус
0) Выход
```

Для обычной установки выбирай `1`.

## Запуск с Windows PowerShell

```powershell
ssh -t -p 22 root@SERVER_IP "curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh"
```

Если SSH-порт нестандартный:

```powershell
ssh -t -p 49222 root@SERVER_IP "curl -fsSL -o /tmp/install-trusttunnel-warp.sh https://raw.githubusercontent.com/GITHUB_USER/REPO_NAME/main/install-trusttunnel-warp.sh && bash /tmp/install-trusttunnel-warp.sh"
```

## Что спросит скрипт

- домен TrustTunnel;
- количество клиентов;
- менять ли SSH-порт;
- новый SSH-порт, по умолчанию `49222`;
- обновлять ли систему перед установкой;
- включать ли WARP;
- включать ли QUIC/HTTP3;
- включать ли fail2ban;
- подтверждение сброса UFW firewall.

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
- `443/tcp` слушается;
- `443/udp` слушается, если включен QUIC/HTTP3;
- WARP public IP отличается от IP VPS.
- `net.ipv4.tcp_congestion_control = bbr`.

## Важно

- Скрипт рассчитан на чистый Ubuntu/Debian VPS.
- Скрипт сбрасывает UFW firewall.
- Открываются только SSH-порт и `443/tcp`.
- Если включен QUIC/HTTP3, дополнительно открывается `443/udp`.
- Самый стабильный режим клиента: HTTP/2.
- Сертификат self-signed, но он встроен в TOML-файлы клиентов.
