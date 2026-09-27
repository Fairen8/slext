# CI/CD: деплой на сервер из GitHub

## Ветки

| Ветка | Назначение |
|---|---|
| `dev` | рабочая: сюда идут все изменения, запускается только статический CI |
| `prod` | **деплой**: push в эту ветку автоматически выкатывает код на сервер |
| `main` | стабильная история; обновляется вручную (merge из `dev`/`prod`) |

## Как выкатить новую версию

```bash
git push origin dev          # изменения
git push origin dev:prod     # выкатить текущий dev на прод (запустит деплой)
```

Пайплайн `.github/workflows/deploy.yml`:

1. **Проверки** — синтаксис Python/JS/Shell (сломанный код не уедет на сервер).
2. **Выгрузка** — `rsync` репозитория на сервер в `/tmp/slext-stage` (по SSH-ключу из секретов).
3. **Применение** — `sudo -n /usr/local/bin/slext-deploy`: идемпотентно собирает новую версию
   в `/opt/slext.new`, сохраняет `slext.env` и `state.json`, делает бэкап `/opt/slext.old`,
   применяет патчи (`apply-injection.sh`), перезапускает API и проверяет `/api/health`.

Ручной запуск: GitHub → Actions → **deploy** → *Run workflow*.

## Одноразовая настройка

### 1. Доступ на сервере

```bash
# на сервере, от root
sudo bash deploy/install-deploy-access.sh fairen8
```

Скрипт ставит `/usr/local/bin/slext-deploy` (root:root 755) и добавляет в
`/etc/sudoers.d/slext-deploy` право запускать **только этот скрипт** без пароля.

### 2. SSH-ключ для деплоя

```bash
# на своей машине
ssh-keygen -t ed25519 -f ~/.ssh/slext_deploy -N ""
ssh-copy-id -i ~/.ssh/slext_deploy.pub -p <SSH_PORT> <SSH_USER>@<SSH_HOST>
```

### 3. Секреты GitHub

В репозитории → Settings → Secrets and variables → Actions добавить:

| Секрет | Значение |
|---|---|
| `SSH_HOST` | адрес сервера |
| `SSH_PORT` | порт SSH |
| `SSH_USER` | пользователь (например, `fairen8`) |
| `SSH_KEY` | приватный ключ деплоя (`~/.ssh/slext_deploy`, целиком) |

Через `gh`:

```bash
gh secret set SSH_HOST -R <owner>/slext --body "<host>"
gh secret set SSH_PORT -R <owner>/slext --body "<port>"
gh secret set SSH_USER -R <owner>/slext --body "<user>"
gh secret set SSH_KEY  -R <owner>/slext < ~/.ssh/slext_deploy
```

## Откат

- Быстрый: на сервере `rm -rf /opt/slext && mv /opt/slext.old /opt/slext && bash /opt/slext/bin/apply-injection.sh && systemctl restart slext-api`.
- Через git: `git revert <commit> && git push origin dev:prod`.

## Замечания

- Деплой выкатывает **весь** репозиторий в staging; из него берутся только `bin/`, `www/`,
  `conf/`, `systemd/`. `slext.env` и `state.json` на сервере не перезаписываются.
- Версия фронтенда берётся из `conf/extver`; панель перезагрузит расширение по `?v=`.
- Если деплой упал на проверке `/api/health`, смотрите лог Actions и
  `journalctl -u slext-api -n 100`.
