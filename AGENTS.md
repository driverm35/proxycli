# Правила для агентов

Стек: Python 3.11+, Rich и Questionary, Caddy 2, 3proxy, Docker Compose, nftables, systemd.
Конфиг: `/etc/proxycli`. Секреты отдельно, режим `0600`. В `state.json` паролей нет.

Нельзя:

- подставлять пользовательские строки в shell; только `subprocess` со списком аргументов
- открывать прокси без пароля
- разрешать через публичные прокси loopback, link-local и metadata
- менять порт SSH или сбрасывать чужие правила файрвола
- писать в журнал пароль или токен DNS
- сообщать об успешном TLS, Docker или установке без реальной проверки

Приватный апстрим вебхука допустим только с явным `--trust-private`.

Проверки:

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
shellcheck -x install.sh uninstall.sh
```

Коммиты короткие, на английском или русском, с причиной изменения.
Секреты, `.env` и токены не коммитить.
