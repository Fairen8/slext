#!/bin/bash
# Временный диагностический скрипт (read-only): challenge 468 на statistics.fairen8.ru
# Запускается через workflow hotfix.yml на сервере SafeLine.
echo "=== whoami ==="
id || true
sudo -n true >/dev/null 2>&1 && echo SUDO_OK || echo SUDO_NO
echo
echo "=== containers ==="
docker ps --format '{{.Names}}' 2>&1 | sort
echo
echo "=== safeline tables ==="
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -tAc \
  "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY 1" 2>&1 | tr '\n' ' '
echo
echo
echo "=== mgt_website columns ==="
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -tAc \
  "SELECT column_name || ' ' || data_type FROM information_schema.columns WHERE table_name='mgt_website' ORDER BY ordinal_position" 2>&1
echo
echo "=== mgt_website rows (id, comment, server_names) ==="
docker exec safeline-pg psql -U safeline-ce -d safeline-ce -c \
  "SELECT id, comment, server_names FROM mgt_website ORDER BY id" 2>&1
echo
echo "=== site configs: protection-related lines ==="
docker exec safeline-tengine sh -c '
for f in /etc/nginx/sites-enabled/IF_*; do
  [ -f "$f" ] || continue
  echo "== $f"
  grep -nE "server_name|t1k|tx_|challenge|human|bot|deny|allow" "$f" | head -60
done' 2>&1
echo
echo "=== tengine config files mentioning challenge/human ==="
docker exec safeline-tengine sh -c \
  'grep -rlnE "human|challenge|slg-|468" /etc/nginx/ 2>/dev/null | head -30' 2>&1
echo
echo "=== panel API endpoints (site/human/bot/challenge/verify) ==="
docker exec safeline-mgt sh -c \
  'grep -rhoE "/api/[A-Za-z0-9_/{}:.-]+" /app/static 2>/dev/null | sort -u | grep -iE "site|human|bot|challenge|verif" | head -100' 2>&1
echo
echo "=== slext health ==="
curl -s -m 5 http://127.0.0.1:8787/api/health 2>&1
echo
echo "=== mgt default.conf (head) ==="
docker exec safeline-mgt sh -c 'head -60 /etc/nginx/conf.d/default.conf 2>/dev/null' 2>&1
echo
echo "=== SLEXT_DIAG_DONE ==="
