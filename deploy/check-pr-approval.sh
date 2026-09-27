#!/bin/bash
# Проверка процесса перед деплоем: пуш в prod/main должен быть результатом
# merge pull request, одобренного владельцем (@Fairen8).
# Используется в CI (deploy.yml, branch-guard.yml). Требует gh + GH_TOKEN.
set -e

REPO="${REPO:-$GITHUB_REPOSITORY}"
SHA="${SHA:-$GITHUB_SHA}"
OWNER="${OWNER:-Fairen8}"

if [ -z "$REPO" ] || [ -z "$SHA" ]; then
  echo "POLICY FAIL: не заданы REPO/SHA"
  exit 1
fi

PR="${POLICY_PR:-$(gh api "repos/$REPO/commits/$SHA/pulls" --jq '.[0].number // empty' 2>/dev/null || true)}"
if [ -z "$PR" ]; then
  echo "POLICY FAIL: коммит $SHA не связан с pull request (прямой пуш?)."
  echo "Правильно: ветка → PR → одобрение @$OWNER → merge в prod."
  exit 1
fi

BASE=$(gh api "repos/$REPO/pulls/$PR" --jq '.base.ref')
HEAD=$(gh api "repos/$REPO/pulls/$PR" --jq '.head.ref')
AUTHOR=$(gh api "repos/$REPO/pulls/$PR" --jq '.user.login')
echo "PR #$PR: $AUTHOR: $HEAD -> $BASE"

if [ "$BASE" != "prod" ] && [ "$BASE" != "main" ]; then
  echo "POLICY FAIL: PR #$PR нацелен на '$BASE', а коммит уехал в prod/main."
  exit 1
fi

# В прод можно мёржить только из main
if [ "$BASE" = "prod" ] && [ "$HEAD" != "main" ]; then
  echo "POLICY FAIL: в prod можно мёржить только из ветки main (PR #$PR: $HEAD -> prod)."
  exit 1
fi

OWNER_STATE=$(gh api "repos/$REPO/pulls/$PR/reviews" \
  --jq "[.[] | select(.user.login==\"$OWNER\")] | last | .state // \"NONE\"")
APPROVERS=$(gh api "repos/$REPO/pulls/$PR/reviews" \
  --jq '[.[] | select(.state=="APPROVED") | .user.login] | unique | join(",")')
echo "Одобрения: ${APPROVERS:-нет} (последнее ревью @$OWNER: $OWNER_STATE)"

if [ "$AUTHOR" = "$OWNER" ]; then
  # PR владельца: достаточно любого одобрения (GitHub запрещает self-approve).
  if [ -z "$APPROVERS" ]; then
    echo "POLICY FAIL: PR #$PR автора @$OWNER не имеет ни одного одобрения."
    exit 1
  fi
else
  # Чужой PR: обязательно одобрение владельца.
  if [ "$OWNER_STATE" != "APPROVED" ]; then
    echo "POLICY FAIL: PR #$PR не одобрен @$OWNER."
    exit 1
  fi
fi

echo "POLICY OK: PR #$PR одобрен, деплой разрешён."
