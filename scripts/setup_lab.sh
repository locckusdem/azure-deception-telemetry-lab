#!/usr/bin/env bash
set -euo pipefail

# Laboratory bootstrap script for Debian 12 (srv-clinica-core)
# Usage: sudo ./scripts/setup_lab.sh

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Run this script as root (sudo $0)." >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_USER="${SOC_TARGET_USER:-marianela_recepcion}"

echo "[*] Creating directory layout under /opt/clinica and /etc/clinica..."
install -d -m 0750 /opt/clinica/bin /opt/clinica/datos /opt/clinica/logs /etc/clinica

echo "[*] Installing orchestrator and environment template..."
install -m 0750 "${REPO_ROOT}/src/soc_orchestrator.py" /opt/clinica/bin/soc_orchestrator.py

if [[ ! -f /etc/clinica/soc-orchestrator.env ]]; then
  install -m 0600 "${REPO_ROOT}/config/soc-orchestrator.env.example" /etc/clinica/soc-orchestrator.env
  echo "[!] Edit /etc/clinica/soc-orchestrator.env to set your SOC_NTFY_URL topic."
fi

if [[ ! -f /opt/clinica/datos/pacientes_db_credenciales.env ]]; then
  install -m 0644 "${REPO_ROOT}/config/pacientes_db_credenciales.env.example" /opt/clinica/datos/pacientes_db_credenciales.env
fi

if ! id "${TARGET_USER}" &>/dev/null; then
  echo "[*] Creating synthetic lab user '${TARGET_USER}'..."
  useradd -m -s /bin/bash "${TARGET_USER}"
fi

echo "[*] Installing auditd rules..."
install -m 0640 "${REPO_ROOT}/auditd/99-medical.rules" /etc/audit/rules.d/99-medical.rules
if command -v augenrules &>/dev/null; then
  augenrules --load
fi

echo "[*] Installing systemd unit..."
install -m 0644 "${REPO_ROOT}/systemd/soc-orchestrator.service" /etc/systemd/system/soc-orchestrator.service
systemctl daemon-reload
systemctl enable --now soc-orchestrator.service

echo "[+] Lab deployment complete. Inspect logs with: journalctl -u soc-orchestrator.service -f"
