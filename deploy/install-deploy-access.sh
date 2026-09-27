#!/bin/bash
# Одноразовая настройка CI/CD-доступа на сервере:
#   1) устанавливает /usr/local/bin/slext-deploy (root:root 755);
#   2) разрешает пользователю запускать только его через sudo без пароля.
#
# Запуск: sudo bash deploy/install-deploy-access.sh [пользователь]
# По умолчанию пользователь: fairen8
set -e

USER_NAME="${1:-fairen8}"
SRC="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" != "0" ]; then
  echo "Запустите от root:  sudo bash deploy/install-deploy-access.sh [user]"
  exit 1
fi

if ! id "$USER_NAME" >/dev/null 2>&1; then
  echo "Пользователь $USER_NAME не существует"
  exit 1
fi

install -o root -g root -m 755 "$SRC/slext-deploy.sh" /usr/local/bin/slext-deploy
printf '%s ALL=(root) NOPASSWD: /usr/local/bin/slext-deploy\n' "$USER_NAME" > /etc/sudoers.d/slext-deploy
chmod 440 /etc/sudoers.d/slext-deploy
visudo -c >/dev/null

mkdir -p /tmp/slext-stage
chown "$USER_NAME" /tmp/slext-stage

echo "OK: установлен /usr/local/bin/slext-deploy и sudoers для $USER_NAME"
echo "Проверка (от имени $USER_NAME): sudo -n /usr/local/bin/slext-deploy"
