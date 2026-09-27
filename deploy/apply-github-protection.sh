#!/bin/bash
# Включает нативную защиту репозитория: rulesets для dev/prod/main + security-настройки.
# Работает на публичных репозиториях (или приватных с GitHub Pro).
# Владелец (текущий gh-пользователь) получает bypass — команда мержится только через ревью.
# Запуск: bash deploy/apply-github-protection.sh [owner/repo]
set -e

REPO="${1:-${REPO:-Fairen8/slext}}"
SRC="$(cd "$(dirname "$0")" && pwd)"
OWNER_ID="$(gh api user --jq .id)"

echo "== Нативная защита для $REPO (bypass для пользователя id=$OWNER_ID) =="

apply_ruleset() {
  local file="$1" tmp
  tmp="$(mktemp)"
  python3 - "$SRC/rulesets/$file" "$OWNER_ID" > "$tmp" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
data['bypass_actors'] = [{"actor_id": int(sys.argv[2]), "actor_type": "User", "bypass_mode": "always"}]
json.dump(data, sys.stdout, ensure_ascii=False)
PY
  echo "  + $file"
  gh api -X POST "repos/$REPO/rulesets" --input "$tmp" >/dev/null
  rm -f "$tmp"
}

echo "[1/5] Rulesets..."
apply_ruleset prod-main.json
apply_ruleset dev.json

echo "[2/5] Окружение production: деплой только после подтверждения владельца"
ENV_TMP="$(mktemp)"
cat > "$ENV_TMP" <<JSON
{
  "wait_timer": 0,
  "reviewers": [ { "type": "User", "id": $OWNER_ID } ],
  "deployment_branch_policy": null
}
JSON
gh api -X PUT "repos/$REPO/environments/production" --input "$ENV_TMP" >/dev/null \
  && echo "  + reviewers: владелец" \
  || echo "  пропущено (нужен публичный репозиторий или GitHub Pro)"
rm -f "$ENV_TMP"

echo "[3/5] Secret scanning + push protection..."
gh api -X PATCH "repos/$REPO" --input "$SRC/security-settings.json" >/dev/null || \
  echo "  пропущено (недоступно на текущем плане)"

echo "[4/5] Dependabot alerts..."
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null 2>&1 || true

echo "[5/5] Автоматические security-фиксы..."
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null 2>&1 || true

echo
echo "Готово. Текущие rulesets:"
gh api "repos/$REPO/rulesets" --jq '.[] | "  #\(.id) \(.name) (\(.enforcement))"'
echo "Текущие окружения:"
gh api "repos/$REPO/environments" --jq '.environments[] | "  \(.name)"'
