#!/bin/bash
# Включает нативную защиту репозитория: rulesets для main/prod + security-настройки.
# Правила: main — рабочая ветка, прямые пуши разрешены (запрет force-push и удаления);
# prod — только из main + подтверждение владельца (Approve или его merge) + чек `tests`.
# Владелец (текущий gh-пользователь) получает bypass — работает напрямую при необходимости.
# Скрипт идемпотентный: существующие rulesets обновляются, устаревшие удаляются.
# Запуск: bash deploy/apply-github-protection.sh [owner/repo]
set -e

REPO="${1:-${REPO:-Fairen8/slext}}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OWNER_ID="$(gh api user --jq .id)"

echo "== Нативная защита для $REPO (bypass для пользователя id=$OWNER_ID) =="

ruleset_id() {
  gh api "repos/$REPO/rulesets" --jq ".[] | select(.name==\"$1\") | .id" 2>/dev/null || true
}

apply_ruleset() {
  local file="$1" tmp name id
  name="$(grep -m1 '"name"' "$SRC/rulesets/$file" | sed -E 's/.*"name" *: *"([^"]+)".*/\1/')"
  id="$(ruleset_id "$name")"
  tmp="$(mktemp)"
  python3 -c "
import json, sys
data = json.load(sys.stdin)
data['bypass_actors'] = [{'actor_id': int(sys.argv[1]), 'actor_type': 'User', 'bypass_mode': 'always'}]
json.dump(data, sys.stdout, ensure_ascii=False)
" "$OWNER_ID" < "$SRC/rulesets/$file" > "$tmp"
  if [ -n "$id" ]; then
    echo "  ~ $file (обновление #$id)"
    gh api -X PUT "repos/$REPO/rulesets/$id" --input "$tmp" >/dev/null
  else
    echo "  + $file (создание)"
    gh api -X POST "repos/$REPO/rulesets" --input "$tmp" >/dev/null
  fi
  rm -f "$tmp"
}

echo "[1/5] Устаревшие rulesets..."
for stale in prod-main-protection dev-protection; do
  sid="$(ruleset_id "$stale")"
  if [ -n "$sid" ]; then
    gh api -X DELETE "repos/$REPO/rulesets/$sid" >/dev/null && echo "  - удалён $stale (#$sid)"
  fi
done

echo "[2/5] Rulesets (main/prod)..."
apply_ruleset main.json
apply_ruleset prod.json

echo "[3/5] Окружение production: без доп. подтверждения, деплой только из ветки prod"
ENV_TMP="$(mktemp)"
cat > "$ENV_TMP" <<JSON
{
  "wait_timer": 0,
  "reviewers": [],
  "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
}
JSON
gh api -X PUT "repos/$REPO/environments/production" --input "$ENV_TMP" >/dev/null \
  && echo "  + подтверждение отключено (старт после tests+policy)" \
  || echo "  пропущено (нужен публичный репозиторий или GitHub Pro)"
rm -f "$ENV_TMP"
PROD_ID="$(gh api "repos/$REPO/environments/production" --jq .id 2>/dev/null || true)"
if [ -n "$PROD_ID" ]; then
  for pid in $(gh api "repos/$REPO/environments/production/deployment-branch-policies" --jq '.branch_policies[].id' 2>/dev/null); do
    gh api -X DELETE "repos/$REPO/environments/production/deployment-branch-policies/$pid" >/dev/null 2>&1 || true
  done
  gh api -X POST "repos/$REPO/environments/production/deployment-branch-policies" \
    -f name=prod -f type=branch >/dev/null 2>&1 \
    && echo "  + деплой в окружение только из ветки prod" \
    || echo "  политика ветки не задана (проверьте настройки окружения)"
fi

echo "[4/5] Secret scanning + push protection..."
gh api -X PATCH "repos/$REPO" --input "$SRC/security-settings.json" >/dev/null || \
  echo "  пропущено (недоступно на текущем плане)"

echo "[5/5] Dependabot alerts + автоматические security-фиксы..."
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null 2>&1 || true
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null 2>&1 || true

echo
echo "Готово. Текущие rulesets:"
gh api "repos/$REPO/rulesets" --jq '.[] | "  #\(.id) \(.name) (\(.enforcement))"'
echo "Текущие окружения:"
gh api "repos/$REPO/environments" --jq '.environments[] | "  \(.name)"'

