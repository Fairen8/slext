# CI/CD: деплой на сервер из GitHub

## Ветки и правила

Поток: **feature → main → prod** (в `prod` — только из `main`).

| Ветка | Назначение | Правила |
|---|---|---|
| `main` | рабочая ветка | **прямые пуши разрешены** (защита только от force-push и удаления); PR — по желанию |
| `prod` | **деплой** | PR **только из `main`**, **подтверждение владельца** (Approve или его merge) и **обязательные тесты `tests`** |
| `feature/*`, `fix/*`, `docs/*` | рабочие ветки | от `main`, живут до мержа |

В `main` пушат напрямую участники с правом записи (роль write). В `prod` напрямую пушить
нельзя: только через PR из `main`, с подтверждением владельца — посторонние с форками могут
лишь предложить PR.

### Тесты — только в прод-пути

Тесты (`tests`) запускаются **исключительно** при мерже в `prod`:

1. **PR в `prod`** — чек `tests` обязателен (ruleset `prod-protection`): пока тесты не прошли,
   кнопка merge недоступна. Это единственный обязательный чек во всём репозитории.
2. **Push в `prod`** (результат мержа) — пайплайн повторно прогоняет те же тесты перед
   выкаткой; при падении job `deploy` не запускается вовсе.

На PR в `main` тесты не гоняются — они не создают шума и не тормозят команду.

### Как это контролируется

1. **Нативные rulesets GitHub** (включаются один раз):

   ```bash
   bash deploy/apply-github-protection.sh
   ```

   - `main`: прямые пуши разрешены, защита только от force-push и удаления;
   - `prod`: PR только из `main` + **подтверждение владельца** (code owner из `CODEOWNERS`)
     + **обязательный чек `tests`**;
   - владелец (текущий `gh`-пользователь) получает bypass — команда не может.

2. **CI-контроль (работает всегда):**
   - `.github/workflows/pipeline.yml` — **единый пайплайн**: `tests → policy → deploy`.
     - `tests` — единственное место с тестами (синтаксис Python/JS/Shell, тесты политики зала,
       валидность rulesets, проверка секретов). Гоняется на PR в `prod` (обязательный чек)
       и повторно перед выкаткой.
     - `policy` — только на push в `prod` (после тестов): PR из `main` с подтверждением
       владельца (Approve-ревью или его merge) — `deploy/check-pr-approval.sh`.
     - `deploy (prod)` — только после `tests` и `policy`; стартует **автоматически**
       (без дополнительных подтверждений), деплоить в окружение можно только из ветки `prod`.
   - `branch-guard.yml` — на каждый пуш в `prod` повторяет проверку процесса; при нарушении
     создаёт issue и красит workflow. Пуши в `main` не контролируются (разрешены напрямую).

Ручной запуск деплоя (Actions → **pipeline** → Run workflow) policy не проверяет — это осознанный
путь для владельца. Тесты при этом всё равно работают.

Дополнительно скрипт включает **secret scanning + push protection** и Dependabot-алерты
(для публичных репозиториев бесплатно).

## Как выкатить новую версию

```bash
git push origin feature/my-task         # рабочая ветка
gh pr create --base main                # PR в main (1 одобрение коллеги; merge/squash)
# после мержа в main:
gh pr create --base prod --head main    # PR в prod (только из main)
#   → автоматически запускаются тесты; без зелёного `tests` merge заблокирован,
#     для prod нужно подтверждение владельца (Approve или его merge)
```

> Мерж в `prod` делается **merge-коммитом** (в ruleset `prod-protection` разрешён только он):
> так история `main` становится частью `prod`, и следующие релизы не конфликтуют.

После мержа в `prod` автоматически запускается **единый пайплайн**
`.github/workflows/pipeline.yml`:

1. **tests** — тесты кода, которые гейтили merge.
2. **policy** — проверка процесса: PR из `main`, подтверждение владельца (Approve или его merge).
3. **deploy (prod)** — только если предыдущие шаги зелёные; стартует автоматически, **без
   дополнительных подтверждений**. Дальше tar-over-ssh в `/tmp/slext-stage` →
   `sudo -n /usr/local/bin/slext-deploy` (бэкап `/opt/slext.old`, сохранение
   `slext.env`/`state.json`, патчи, restart API, health-check).

Любой упавший шаг блокирует следующий: упали тесты — деплоя нет; policy не пройдена — деплоя нет.

Ручной запуск: GitHub → Actions → **pipeline** → *Run workflow* (policy пропускается,
тесты работают; запускать с ветки `prod`).

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
вместо дополнительного «approve» на окружении включена **политика деплой-ветки**: использовать
окружение (и его секреты) можно только из ветки `prod` — запуск пайплайна с любой другой ветки
отклоняется.

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
