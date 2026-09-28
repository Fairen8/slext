# Архитектура

## Общая схема

```
┌──────────────┐   HTTPS 9443    ┌───────────────────────┐
│  Браузер      │ ───────────────▶│ safeline-mgt (панель)  │
│  (панель)     │                 │  React SPA + nginx     │
└──────────────┘                 │   └─ /extapi ──────────┼──▶ slext-api.py :8787
                                 └───────────────────────┘        (127.0.0.1)
                                                                     │
┌──────────────┐   HTTP/HTTPS    ┌───────────────────────┐          │
│  Посетители   │ ───────────────▶│ safeline-tengine       │          │
│  сайта        │                 │  nginx + SafeLine WAF  │          │
└──────────────┘                 │   ├─ сайт (backend_1)  │◀─────────┘
                                 │   └─ slext_traffic.log │  (patches, DB, docker)
                                 └───────────────────────┘
                                             │
                                   ┌─────────┴─────────┐
                                   │ safeline-pg (БД)   │
                                   └───────────────────┘
```

- **`slext-api.py`** — собственный HTTP API (stdlib `ThreadingHTTPServer`) на `127.0.0.1:8787`.
  Аутентификация — Bearer-токен панели SafeLine (проверяется через mgt API
  `/api/business/account`, из JWT берётся `Username` для матрицы доступа). Панель ходит в API
  через прокси `/extapi` в nginx контейнера `safeline-mgt`.
- **`ext.js` / `ext.css`** — расширение панели: вкладка **SLExt** в левом меню и одноимённая
  рабочая область. Встраиваются в `index.html` панели (patch_index.py) с версионированием
  `?v=<extver>`.
- **`apply-injection.sh`** — идемпотентный деплой: копирует ассеты в контейнер, патчит
  конфиг сайта, конфигурирует проксю `/extapi`, подкладывает стили и страницы.
- **systemd**: `slext-api.service` (API), `slext-apply.timer` (переприменение раз в 2 минуты),
  `slext-apply.path` (вотчдог: реагирует на изменение каталога `sites-enabled` — возвращает
  патчи за ~секунду после перегенерации конфигов SafeLine).

## Фоновые воркеры API

| Воркер | Период | Задачи |
|---|---|---|
| `notify_worker` | 30 с | уведомления Telegram/Discord по алертам (пороги метрик) |
| `lb_worker` | 30 с | health-check upstream-балансировщика, авто-переключение |
| `alarm_worker` | 60 с | правила алертов (атаки, блокировки, высокий риск) |
| `backup_worker` | 60 с | автобэкапы конфигурации SLExt |
| `waiting_worker` | 20 с | зал ожидания: сверка факта с SafeLine, детерминированный авто-режим (политика — `bin/wr_policy.py`), ретраи, восстановление патчей сайта (`site_patch_fast`) |
| `dns_worker` | 300 с | проверки DNS/TLS по доменам сайтов (история — 2 суток) |

Все данные хранятся в `state.json` (атомарная запись, права `600`). Ключи: `access, alarm,
backup, dns, geo, lb, loadtest, notify, page, skip, syslog, waiting`.

## Патчи nginx-конфига сайта

Конфигурация сайта SafeLine (`/data/safeline/resources/nginx/sites-enabled/IF_*`) патчится
функциями `patch_site_page.py`. Каждая вставка маркирована комментарием `# slext-*`; повторный
запуск ничего не дублирует. Маркеры:

| Маркер | Назначение |
|---|---|
| `# slext-page` | алиасы кастомных страниц ошибок (403/404/429/465/466/502/504) |
| `# slext-page-intercept` | `proxy_intercept_errors on` для перехвата ошибок бэкенда |
| `# slext-enc-pipeline` | `proxy_set_header Accept-Encoding ""` (фикс сломанных сжатием страниц расшифровки) |
| `# slext-nf404`, `# slext-nf404-off` | HTML-навигация для 404 через свою страницу, API — проход как есть |
| `# slext-challenge-css` | свой `challenge.css` для страницы Anti-Bot |
| `# slext-dynamic-css` | свой `dynamic.css` для страницы расшифровки |
| `# slext-skip`, `# slext-skip-plain`, `# slext-skip-cc` | skip decryption: bypass по cookie, локация `/@slext-plain`, no-store для HTML |
| `# slext-gate`, `# slext-gate-loc` | гейт первого захода (без `document.write`) |
| `# slext-px-format`, `# slext-px-access` | собственный access_log прокси с таймингами (`slext_traffic.log`) |

Дополнительно в `conf.d/` создаются карты: `zz_slext_nf.conf`, `zz_slext_skip.conf`,
`zz_slext_cc.conf`, `zz_slext_gate.conf` (полное описание — в [configuration.md](configuration.md)).

## Потоки данных

### 1. Панель → API
Браузер → `/extapi/api/...` (nginx `safeline-mgt`) → `slext-api:8787`. Токен — из localStorage
панели (`safeline_auth`), передаётся заголовком `Authorization: Bearer`.

### 2. Запросы сайта (skip decryption)
1. Первый заход (нет cookie, `Accept: text/html`) → map `$slext_gate` → `gate.html` (1801 б):
   проверка клиента JS, установка cookie `nrgpass=1`, `location.replace` на ту же страницу.
2. Повторный заход с cookie (или cookie SafeLine) → map `$slext_skip` → `/@slext-plain`
   (`tx_chaos_intercept off`) → бэкенд напрямую: ни страницы расшифровки, ни `document.write`.
3. Не-HTML или GET от API без cookie → штатный проход через WAF (шифрование сохраняется).

### 3. Прокси-аналитика
nginx пишет собственный `slext_traffic.log` (формат `slext_px`: IP, время, host, запрос, статус,
байты, `request_time`, `upstream_response_time`, UA, referer). API парсит его (с ротацией
>100 МБ), считает RPS, перцентили, Apdex, ошибки, накладные расходы WAF, топы и динамику.

### 4. Тест ёмкости
API-движок (потоки) поэтапно увеличивает параллелизм, замеряет RPS/перцентили/ошибки.
Режимы: **напрямую в бэкенд** (по умолчанию, защита не затрагивается) или **через WAF**
с авто-паузой защиты (временно выключаются частотные правила SafeLine и CrowdSec-бансер,
после теста всё возвращается). Отчёты уходят в архив (10 последних).

### 5. Закрытие/удаление
`uninstall.sh` останавливает службы и удаляет файлы; конфиги nginx восстанавливаются из
`slext-orig`-бэкапа, если он есть (создаётся при первой установке на «чистом» конфиге),
иначе — предупреждение.

## Версионирование

- `conf/extver` — текущая версия фронтенда (например, `39`).
- `index.html` панели ссылается на `ext.js?v=<extver>`; `versionCheck()` в ext.js сверяет
  версию с `/api/health` и перезагружает панель после обновления.
- API отдаёт `extver` в `/api/health`.
