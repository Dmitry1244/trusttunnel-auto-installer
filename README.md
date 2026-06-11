# TrustTunnel + WARP installer

Интерактивный установщик TrustTunnel endpoint для Ubuntu/Debian VPS.

Что настраивает:

- TrustTunnel на `443/tcp`;
- обновление системы перед установкой;
- WARP через `wireproxy`, чтобы сайты видели WARP/Cloudflare IP, а не IP VPS;
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
- включать ли fail2ban;
- подтверждение сброса UFW firewall.

## Где будут клиенты

После установки на сервере:

```text
/root/trusttunnel-clients/
/root/trusttunnel-clients-YOUR_DOMAIN.zip
```

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
- WARP public IP отличается от IP VPS.
- `net.ipv4.tcp_congestion_control = bbr`.

## Важно

- Скрипт рассчитан на чистый Ubuntu/Debian VPS.
- Скрипт сбрасывает UFW firewall.
- Открываются только SSH-порт и `443/tcp`.
- Рабочий стабильный режим клиента: HTTP/2.
- QUIC/HTTP3 в этом варианте не включается.
- Сертификат self-signed, но он встроен в TOML-файлы клиентов.
