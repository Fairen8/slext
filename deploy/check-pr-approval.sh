#!/bin/bash
# Проверка процесса для защищённых веток (pipeline.yml, branch-guard.yml):
#   * prod — только из main и только с одобрением владельца (@Fairen8);
#     merge владельца в prod разрешён без сторонних одобрений (он и есть approver).
#   * main — обычный PR с одобрением любого участника; одобрение владельца НЕ требуется;
#     merge самого владельца разрешён (bypass).
# Требует gh + GH_TOKEN.
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
  echo "Правильно: ветка → PR → merge (в prod — с одобрением @$OWNER)."
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

APPROVERS=$(gh api "repos/$REPO/pulls/$PR/reviews" \
  --jq '[.[] | select(.state=="APPROVED") | .user.login] | unique | join(",")')
MERGED_BY=$(gh api "repos/$REPO/pulls/$PR" --jq '.merged_by.login // ""')
echo "Одобрения: ${APPROVERS:-нет}; merge выполнил: ${MERGED_BY:-—}"

if [ "$BASE" = "prod" ]; then
  # В прод можно мёржить только из main.
  if [ "$HEAD" != "main" ]; then
    echo "POLICY FAIL: в prod можно мёржить только из ветки main (PR #$PR: $HEAD -> prod)."
    exit 1
  fi
  # Подтверждение владельца для prod: либо ревью Approve от него, либо его собственный merge.
  if [ "$AUTHOR" != "$OWNER" ] && [ "$MERGED_BY" != "$OWNER" ]; then
    OWNER_STATE=$(gh api "repos/$REPO/pulls/$PR/reviews" \
      --jq "[.[] | select(.user.login==\"$OWNER\")] | last | .state // \"NONE\"")
    if [ "$OWNER_STATE" != "APPROVED" ]; then
      echo "POLICY FAIL: PR #$PR в prod не одобрен @$OWNER (нужен Approve или merge владельца)."
      exit 1
    fi
  fi
  echo "POLICY OK: PR #$PR (прод) — процесс соблюдён."
else
  # main: merge участника должен быть через PR с хотя бы одним одобрением;
  # одобрение владельца не требуется. Merge самого владельца разрешён.
  if [ "$AUTHOR" != "$OWNER" ] && [ "$MERGED_BY" != "$OWNER" ] && [ -z "$APPROVERS" ]; then
    echo "POLICY FAIL: PR #$PR в main не имеет ни одного одобрения участника."
    exit 1
  fi
  echo "POLICY OK: PR #$PR (main) — процесс соблюдён."
fi
