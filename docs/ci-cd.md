# CI/CD: деплой на сервер из GitHub

## Ветки и правила

| Ветка | Назначение | Правила |
|---|---|---|
| `dev` | рабочая интеграция | PR + 1 одобрение, проверки CI |
| `prod` | **деплой** | PR **только с одобрением владельца (@Fairen8)**, проверки CI |
| `main` | стабильная история | как `prod` |
| `feature/*`, `fix/*`, `docs/*` | рабочие ветки | от `dev`, живут до мержа |

### Как это контролируется

Два уровня защиты:

1. **Нативные rulesets GitHub** (работают в публичном репозитории, а в приватном — только
   с GitHub Pro). Включаются один раз:

   ```bash
   bash deploy/apply-github-protection.sh
   ```

   Что настраивается:
   - `dev`: PR + 1 одобрение, обязательные проверки CI, запрет force-push и удаления;
   - `prod` и `main`: PR **только с одобрением владельца** (code owner из `CODEOWNERS`),
     обязательные проверки, linear history, запрет force-push и удаления;
   - владелец (текущий `gh`-пользователь) получает bypass — команда не может.

2. **CI-контроль (работает всегда):**
   - `deploy.yml` → job `policy` — перед выкаткой проверяет, что пуш в `prod` является
     результатом PR, одобренного владельцем (`deploy/check-pr-approval.sh`). Нет PR или
     нет одобрения → деплой не запускается.
   - `branch-guard.yml` — на каждый пуш в `prod`/`main` повторяет проверку; при нарушении
     создаёт issue и красит workflow.

Ручной запуск деплоя (Actions → deploy → Run workflow) policy не проверяет — это осознанный
путь для владельца.

Дополнительно скрипт включает **secret scanning + push protection** и Dependabot-алерты
(для публичных репозиториев бесплатно).

## Как выкатить новую версию

```bash
git push origin feature/my-task        # рабочая ветка
gh pr create --base dev                # PR в dev (1 одобрение)
# после мержа в dev:
gh pr create --base prod --head dev    # PR в prod → одобрение владельца → merge
```

После мержа в `prod` автоматически запускается `.github/workflows/deploy.yml`:

1. **policy** — проверка PR и одобрения владельца.
2. **checks** — синтаксис Python/JS/Shell.
3. **deploy** — tar-over-ssh в `/tmp/slext-stage` → `sudo -n /usr/local/bin/slext-deploy`
   (новая версия в `/opt/slext.new`, сохранение `slext.env`/`state.json`, бэкап `/opt/slext.old`,
   патчи, restart API, health-check).

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

SSH-доступ деплоя хранится **на уровне окружения `production`** (не репозитория), чтобы его
нельзя было получить из произвольных workflow/веток. Значения секретов не отображаются никому;
после публикации репозитория на окружении включается **обязательное подтверждение владельца** —
без approve деплой (и секреты) недоступны.

```bash
gh secret set SSH_HOST --env production -R <owner>/slext --body "<host>"
gh secret set SSH_PORT --env production -R <owner>/slext --body "<port>"
gh secret set SSH_USER --env production -R <owner>/slext --body "<user>"
gh secret set SSH_KEY  --env production -R <owner>/slext < ~/.ssh/slext_deploy
```

Репозиторные секреты не используются. Команде выдавайте роль **write** — тогда они смогут
работать только через PR.

## Откат

- Быстрый: на сервере `rm -rf /opt/slext && mv /opt/slext.old /opt/slext && bash /opt/slext/bin/apply-injection.sh && systemctl restart slext-api`.
- Через git: `git revert <commit> && git push origin dev:prod`.

## Замечания

- Деплой выкатывает **весь** репозиторий в staging; из него берутся только `bin/`, `www/`,
  `conf/`, `systemd/`. `slext.env` и `state.json` на сервере не перезаписываются.
- Версия фронтенда берётся из `conf/extver`; панель перезагрузит расширение по `?v=`.
- Если деплой упал на проверке `/api/health`, смотрите лог Actions и
  `journalctl -u slext-api -n 100`.
