# CI/CD: деплой на сервер из GitHub

## Ветки и правила

Поток: **feature → main → prod** (в `prod` можно мёржить только из `main`).

| Ветка | Назначение | Правила |
|---|---|---|
| `main` | рабочая интеграция и стабильная | PR **только для участников** + **1 одобрение участника**; одобрение владельца **не требуется**, запрет force-push, linear history |
| `prod` | **деплой** | PR **только из `main`**, **одобрение владельца** и **обязательные тесты `tests`** — без них merge заблокирован |
| `feature/*`, `fix/*`, `docs/*` | рабочие ветки | от `main`, живут до мержа |

«Только для участников» обеспечивается тем, что прямые пуши в `main`/`prod` запрещены
(rulesets), а мёржить PR может только владелец/участники с правом записи; посторонние с
форками могут лишь предложить PR. **Одобрение владельца требуется только для `prod`** —
мержи команды в `main` выполняются с одобрением любого участника.

### Тесты — только в прод-пути

Тесты (`tests`) запускаются **исключительно** при мерже в `prod`:

1. **PR в `prod`** — чек `tests` обязателен (ruleset `prod-protection`): пока тесты не прошли,
   кнопка merge недоступна. Это единственный обязательный чек во всём репозитории.
2. **Push в `prod`** (результат мержа) — `deploy.yml` повторно прогоняет те же тесты перед
   выкаткой; при падении job `deploy` не запускается вовсе.

На PR в `main` тесты не гоняются — они не создают шума и не тормозят команду.

### Как это контролируется

1. **Нативные rulesets GitHub** (включаются один раз):

   ```bash
   bash deploy/apply-github-protection.sh
   ```

   - `main`: PR + 1 одобрение участника (владелец не требуется), linear history,
     запрет force-push и удаления;
   - `prod`: PR только из `main` + **одобрение владельца** (code owner из `CODEOWNERS`) +
     **обязательный чек `tests`**;
   - владелец (текущий `gh`-пользователь) получает bypass — команда не может.

2. **CI-контроль (работает всегда):**
   - `ci.yml` → job `tests` — единственное место с тестами (синтаксис Python/JS/Shell,
     валидность rulesets, проверка секретов). Вызывается из `deploy.yml` как reusable.
   - `deploy.yml` → job `policy` — перед выкаткой проверяет, что пуш в `prod` является
     результатом PR **из `main`** с подтверждением владельца: подходит **Approve-ревью
     владельца или его собственный merge** (`deploy/check-pr-approval.sh`).
   - `branch-guard.yml` — на каждый пуш в `prod`/`main` повторяет проверку; для `main`
     достаточно PR с одобрением участника (одобрение владельца не требуется); при нарушении
     создаёт issue и красит workflow.

Ручной запуск деплоя (Actions → deploy → Run workflow) policy не проверяет — это осознанный
путь для владельца. Тесты и подтверждение окружения при этом всё равно работают.

Дополнительно скрипт включает **secret scanning + push protection** и Dependabot-алерты
(для публичных репозиториев бесплатно).

## Как выкатить новую версию

```bash
git push origin feature/my-task         # рабочая ветка
gh pr create --base main                # PR в main (1 одобрение коллеги)
# после мержа в main:
gh pr create --base prod --head main    # PR в prod (только из main)
#   → автоматически запускаются тесты; без зелёного `tests` merge заблокирован,
#     для prod нужно подтверждение владельца (Approve или его merge)
```

После мержа в `prod` автоматически запускается `.github/workflows/deploy.yml`:

1. **policy** — проверка: PR из `main`, одобрен владельцем.
2. **tests** — те же тесты, что гейтили merge (reusable `ci.yml`).
3. **deploy (prod)** — только если предыдущие шаги зелёные, и после **подтверждения
   окружения `production`** владельцем. Дальше tar-over-ssh в `/tmp/slext-stage` →
   `sudo -n /usr/local/bin/slext-deploy` (бэкап `/opt/slext.old`, сохранение
   `slext.env`/`state.json`, патчи, restart API, health-check).

Любой упавший шаг блокирует следующий: упали тесты — деплоя нет; нет одобрения — деплоя нет.

Ручной запуск: GitHub → Actions → **deploy** → *Run workflow* (policy пропускается,
тесты и подтверждение окружения остаются).

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
- Через git: revert в `main` (PR), затем `main → prod` (PR) — деплой откатит версию.

## Замечания

- Деплой выкатывает **весь** репозиторий в staging; из него берутся только `bin/`, `www/`,
  `conf/`, `systemd/`. `slext.env` и `state.json` на сервере не перезаписываются.
- Версия фронтенда берётся из `conf/extver`; панель перезагрузит расширение по `?v=`.
- Если деплой упал на проверке `/api/health`, смотрите лог Actions и
  `journalctl -u slext-api -n 100`.
