# CI/CD: деплой на сервер из GitHub

## Ветки и защита

| Ветка | Назначение | Правила (branch protection) |
|---|---|---|
| `dev` | рабочая интеграция | PR с 1 одобрением, обязательные проверки CI, force-push запрещён |
| `prod` | **деплой** | PR **только с одобрением владельца** (code owner @Fairen8), проверки CI, squash/linear, force-push запрещён |
| `main` | стабильная история | как `prod` |

Напрямую пушить нельзя ни в одну из веток — только через pull request
(администратор может обойти правило при необходимости).

## Как выкатить новую версию

```bash
git push origin feature/my-task        # рабочая ветка
gh pr create --base dev                # PR в dev (1 одобрение)
# после мержа в dev:
gh pr create --base prod --head dev    # PR в prod → одобрение владельца → merge
```

После мержа в `prod` автоматически запускается `.github/workflows/deploy.yml`:

1. **Проверки** — синтаксис Python/JS/Shell.
2. **Выгрузка** — tar-over-ssh в `/tmp/slext-stage`.
3. **Применение** — `sudo -n /usr/local/bin/slext-deploy`: новая версия в `/opt/slext.new`,
   сохранение `slext.env`/`state.json`, бэкап `/opt/slext.old`, патчи, restart API, health-check.

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
