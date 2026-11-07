#!/usr/bin/env bash
set -euo pipefail

# Account recovery & remediation runbook helper after PAM containment.
# Should only be executed by an administrator after verifying root cause
# and rotating potentially compromised passwords / SSH authorized keys.
#
# Usage: sudo ./scripts/recover_account.sh <username> [--force-password-reset]

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Run this script as root (sudo $0 <username>)." >&2
  exit 1
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <username> [--force-password-reset]" >&2
  exit 2
fi

USERNAME="$1"
FORCE_RESET="${2:-}"

if ! id "${USERNAME}" &>/dev/null; then
  echo "[!] User '${USERNAME}' does not exist." >&2
  exit 1
fi

echo "[*] Restoring account expiration, interactive shell, and password lock for '${USERNAME}'..."
usermod --expiredate "" "${USERNAME}"
chsh -s /bin/bash "${USERNAME}"
passwd -u "${USERNAME}" || true

if [[ "${FORCE_RESET}" == "--force-password-reset" ]]; then
  chage -d 0 "${USERNAME}"
  echo "[*] Password rotation enforced on next login (chage -d 0)."
fi

echo "[!] Manual checklist remaining before re-enabling access:"
echo "    1. Review and rotate SSH keys in ~${USERNAME}/.ssh/authorized_keys"
echo "    2. Document remediation status for the corresponding CMS-INC ticket"
