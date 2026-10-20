# ProxyCLI

Русскоязычная консольная утилита для одного европейского VPS. Она ставит Caddy 2
и 3proxy в Docker и управляет ими из меню: HTTPS reverse proxy, SOCKS5 и
HTTP-прокси с HTTPS CONNECT.

Веб-панели, Kubernetes и отдельные базы данных не используются. Настройки лежат
в JSON, пароли — в отдельном файле с правами `0600`.

## Что нужно от VPS

- Ubuntu 24.04, Ubuntu 26.04 или Debian 13
- amd64 или arm64
- публичный IPv4
- свободные порты 80 и 443 для Caddy
- root по SSH
- исходящий доступ в интернет

Порты SOCKS5 и HTTP-прокси по умолчанию: `1080` и `3128`. Порт SSH не меняется.

## Установка одной командой

```bash
curl -fsSL https://raw.githubusercontent.com/driverm35/proxycli/main/install.sh | sudo bash
```

Если установщик запущен из терминала, откроется меню. Если команда пришла по
каналу `curl | bash`, меню не запускается. Дальше:

```bash
sudo proxycli
```

Повторный запуск `install.sh` не удаляет `/etc/proxycli/config.json` и `/etc/proxycli/secrets.json`.

Каталоги:

- программа: `/opt/proxycli`
- конфиг и секреты: `/etc/proxycli/config.json`, `/etc/proxycli/secrets.json`
- журнал: `/var/log/proxycli`
- рабочие файлы Docker: `/var/lib/proxycli/deploy`
- резервные копии: `/var/lib/proxycli/backups`

Проверка без установки:

```bash
bash install.sh --dry-run
```

## Меню

```text
ProxyCLI 1.0.0
Caddy: не проверено (offline)
3proxy: не проверено (offline)

Главное меню
  1. Вебхуки и маршруты
  2. SOCKS5
  3. HTTP-прокси
  4. Диагностика
  5. Настройки
  6. Обновление ProxyCLI
  7. Журнал событий
  0. Выход
```

Стрелки и Enter выбирают пункт, Esc возвращает назад, Ctrl+C выходит.
Без UTF-8 и при `NO_COLOR` или `TERM=dumb` остаётся текстовый список.

## DNS

Для вебхуков нужен домен, например `hooks.example.com`, и запись:

```text
*.hooks.example.com.   A   <публичный IPv4 сервера>
```

Это DNS-запись. Сама по себе она не выпускает wildcard-сертификат.

Режим A (по умолчанию): отдельный сертификат на каждый поддомен через
HTTP-01 или TLS-ALPN-01.

Режим B: wildcard-сертификат через DNS-01 и токен Cloudflare. Токен пишется
только в файл секретов. Если сборка Caddy с модулем `dns.providers.cloudflare`
не подтверждена, ProxyCLI остаётся в режиме A и прямо говорит, что wildcard TLS
не выпущен.

## Первый вебхук

```bash
sudo proxycli wizard \
  --public-ip 203.0.113.10 \
  --domain hooks.example.com \
  --tls-mode http \
  --acme-email admin@example.com

sudo proxycli routes add \
  --subdomain telegram \
  --upstream http://10.1.2.3:5678 \
  --trust-private
```

Приватный апстрим сохраняется только с `--trust-private`. Вопрос про
приватный апстрим задаётся только для частного адреса. Адреса loopback,
link-local и metadata (в том числе `169.254.169.254` и
`metadata.google.internal`) запрещены всегда.

В URL апстрима допустимы порт и базовый путь, например
`https://api.example.com/admin/telegram/webhook/`. Caddy сохраняет метод и
query. Входящий путь дописывается к этому базовому пути: запрос на
`https://telegram.hooks.example.com/extra?x=1` уходит на
`/admin/telegram/webhook/extra?x=1`. Если базового пути нет, путь и query
проходят без rewrite. Для Telegram в setWebhook укажите только хост, без пути.
Если апстрим не отвечает по DNS, TCP или TLS, маршрут можно сохранить:
в меню подтвердите это, в команде добавьте `--inactive`. Ответы 401, 403 и
404 не считаются мёртвым апстримом. Это обратный HTTP-прокси: он завершает
TLS клиента и не обещает побайтово те же заголовки или сквозной TLS.

## SOCKS5

Один процесс 3proxy и один порт на всех пользователей.

```bash
sudo proxycli socks add-user --username alice
sudo proxycli socks reveal --username alice --i-understand
sudo proxycli socks example --username alice
sudo proxycli socks allow --user alice --cidr 203.0.113.10
sudo proxycli socks inspect-acl --source 203.0.113.10
```

Allowlist общий для всех пользователей одного прокси: логин и пароль
нужны всегда, адрес клиента должен входить в список. `inspect-acl` без
паролей показывает ACL, свежесть контейнера, DNAT Docker и последние отказы
3proxy с адресом, который 3proxy реально видит. Код 3 значит, что адрес не в
allowlist, код 6 означает неверный пароль, код 4 означает отсутствие логина.

Пароль в журнале маскируется. В терминале без OSC52 строка для копирования
печатается только по явному запросу.

## HTTP-прокси

```bash
sudo proxycli http add-user --username bob
sudo proxycli http example --username bob
```

Пример curl показывает пароль как `****`. Авторизация обязательна: анонимный
прокси не поднимается. Пароль между клиентом и прокси идёт без TLS. Для
доступа из интернета нужен отдельный защищённый канал.

## Диагностика, обновление, удаление

```bash
sudo proxycli status
sudo proxycli doctor
sudo proxycli version
sudo proxycli update --check
sudo proxycli update --apply
sudo bash /opt/proxycli/uninstall.sh
sudo bash /opt/proxycli/uninstall.sh --purge --yes
```

`doctor` ограничивает каждую проверку таймаутом. `update --apply` сначала
делает резервную копию и не стирает маршруты и пароли. Откат файрвола удаляет
только правила с меткой ProxyCLI и не выполняет `nft flush ruleset`.

Без `--purge` каталог `/etc/proxycli` сохраняется. Docker Engine и SSH
удаление не трогает.

## Если установка остановилась

Скрипт печатает строку и команду диагностики. Частые причины: не root, другая
ОС, заняты порты 80 или 443 чужим процессом, нет доступа к GitHub.

```bash
cat /etc/os-release
uname -m
ss -ltnp | head
sudo proxycli doctor
```

## Что не проверялось на живом VPS

В этой сборке не выполнялась установка на чистый публичный VPS и не
выпускался настоящий сертификат Let's Encrypt. Контейнерный smoke-тест
3proxy запускается только если локально доступен Docker; иначе тест
пропускается и успех не подменяется. Проверки генерации Caddyfile, конфига
3proxy, отката неудачного reload, валидации ввода и разбора `install.sh`
выполняются локально и в GitHub Actions.
