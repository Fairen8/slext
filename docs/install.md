# Установка

## Требования

| Компонент | Требование |
|---|---|
| ОС | Debian/Ubuntu (apt) или совместимая, systemd |
| CPU | x86_64 или arm64 c поддержкой **ssse3** (требование SafeLine) |
| Docker | установлен и запущен |
| SafeLine | **WAF CE** (docker-стек: `safeline-mgt`, `safeline-tengine`, `safeline-pg`) |
| Python | `python3` + `psycopg2` (install.sh поставит `python3-psycopg2`) |
| Прочее | `openssl`, `curl`, доступ к GitHub (репозиторий приватный) |

Место на диске: ~50 МБ (без учёта логов аналитики).

## Установка

### Вариант A. Поверх установленной SafeLine (частый случай)

```bash
gh repo clone Fairen8/slext /tmp/slext && cd /tmp/slext && sudo bash install.sh
```

Если на сервере нет `gh`, клонируйте репозиторий у себя и скопируйте на сервер:

```bash
scp -r slext root@SERVER:/tmp/ && ssh root@SERVER "bash /tmp/slext/install.sh"
```

### Вариант B. Чистый сервер

```bash
gh repo clone Fairen8/slext /tmp/slext && cd /tmp/slext && sudo bash install.sh --with-safeline
```

Скрипт вызовет официальный инсталлятор SafeLine CE
(`https://waf.chaitin.com/release/latest/setup.sh`, документация:
<https://docs.waf.chaitin.com/en/GetStarted/Deploy>), дождётся контейнеров и продолжит установку SLExt.

## Что делает install.sh

1. Проверяет наличие контейнеров SafeLine (или устанавливает её с `--with-safeline`).
2. Ставит зависимости: `python3-psycopg2`, `openssl` (если нет).
3. Копирует `bin/`, `www/`, `conf/` в `/opt/slext`.
4. Создаёт `/opt/slext/conf/slext.env` (пароль PostgreSQL берётся из контейнера `safeline-pg`).
5. Устанавливает и включает systemd-юниты: `slext-api.service`, `slext-apply.path`, `slext-apply.timer`.
6. Запускает `apply-injection.sh`: патчит конфиг сайта SafeLine, подкладывает страницы и стили,
   включает прокси `/extapi` в панели, перезагружает nginx (с предварительной проверкой `nginx -t`).
7. Проверяет `http://127.0.0.1:8787/api/health`.

## Ручная установка (эквивалент)

```bash
mkdir -p /opt/slext
cp -a bin www conf /opt/slext/
cat > /opt/slext/conf/slext.env <<EOF
PGHOST=127.0.0.1
PGUSER=safeline-ce
PGPASSWORD=$(docker exec safeline-pg printenv POSTGRES_PASSWORD)
PGDATABASE=safeline-ce
EOF
chmod 600 /opt/slext/conf/slext.env
cp systemd/* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now slext-api.service slext-apply.path slext-apply.timer
bash /opt/slext/bin/apply-injection.sh
```

## Проверка после установки

```bash
systemctl is-active slext-api                 # active
curl -s http://127.0.0.1:8787/api/health      # {"ok": true, ..., "extver": "..."}
bash tests/verify-install.sh                  # полный smoke-тест
```

В панели SafeLine: обновить страницу (Ctrl+F5) → в левом меню появится пункт **SLExt** →
открыть, проверить статус в шапке (зал ожидания / skip), раздел «Доступ» (кто вошёл).

## Обновление

```bash
cd /path/to/slext && git pull
sudo bash install.sh
```

Повторный запуск идемпотентен: файлы обновляются, патчи не дублируются, nginx перезагружается
только если конфиг реально изменился. Версия фронтенда поднимается в `conf/extver`, панель
автоматически перезагрузится при следующем обращении.

## Удаление

```bash
sudo bash uninstall.sh            # интерактивно
sudo bash uninstall.sh --yes      # без подтверждения
```

Что делает: останавливает и удаляет службы, удаляет `/opt/slext`, убирает ссылки `ext.js/ext.css`
из `index.html` панели. Конфиги nginx сайта восстанавливаются из бэкапа `IF_*.slext-orig`,
если он существует (создаётся при первой установке на «чистом» конфиге); иначе выводится
предупреждение — патчи безопасны и перестанут применяться после перегенерации конфига SafeLine.

## После установки: первичная настройка

1. **SafeLine**: добавить сайт (Applications → Add Application), если ещё не добавлен.
   Вотчдог `slext-apply.path` применит патчи к новому конфигу в течение секунды.
2. **SLExt → Настройки разделов**:
   - «Страницы» — бренд, цвет, тексты страниц ошибок;
   - «Безопасность» — skip decryption (вкл) и гео-блокировка;
   - «Уведомления» — Telegram/Discord, алерты, syslog, бэкапы;
   - «Доступ» — роли и домены для пользователей панели.
