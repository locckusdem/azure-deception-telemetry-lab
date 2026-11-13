# Lab Validation Playbook

This playbook reproduces the two *Assume Breach* validation scenarios executed on `srv-clinica-core` (Debian 12) and verifies end-to-end detection, PAM containment, JSONL ticket generation, and `ntfy.sh` alerting.

> **Safety Note:** Always run automated unit tests first (`python3 -m unittest discover -s tests -v`), or test the orchestrator with `--dry-run` before enabling live PAM lockouts on a host.

---

## Prerequisites

1. Deploy lab artifacts on Debian 12:
   ```bash
   sudo ./scripts/setup_lab.sh
   ```
2. Verify `auditd` rule is loaded:
   ```bash
   sudo auditctl -l | grep honeytoken_acceso
   ```
3. Verify `soc-orchestrator.service` is active:
   ```bash
   sudo systemctl status soc-orchestrator.service
   ```
4. Keep an administrative SSH session open on a **separate admin account** (e.g., `<admin_user>` on `TCP/2222`) to observe logs and restore the test account between scenarios.

---

## Scenario 1: Honeytoken Credential Access (`HONEYTOKEN_READ`)

Simulates an attacker with valid SSH access enumerating configuration files for database credentials.

1. Connect as the simulated compromised user:
   ```bash
   ssh -p 2222 marianela_recepcion@<VM_IP>
   ```
2. Trigger the kernel-monitored decoy file:
   ```bash
   cat /opt/clinica/datos/pacientes_db_credenciales.env
   ```
3. **Expected Result:**
   - `auditd` logs a syscall under key `honeytoken_acceso` for `UID 1001`.
   - `soc_orchestrator.py` locks the account and sends `SIGKILL` to active sessions.
   - The attacker SSH terminal closes immediately:
     ```text
     Connection to <VM_IP> closed by remote host.
     ```
   - Re-authentication (even with a valid SSH key) is denied by PAM:
     ```text
     Your account has expired; please contact your system administrator.
     ```
   - A `HONEYTOKEN_READ` ticket is appended to `/opt/clinica/logs/soc_actions.log` and delivered via `ntfy.sh`.

---

## Reset Between Scenarios

From the administrative session:

```bash
sudo ./scripts/recover_account.sh marianela_recepcion
sudo systemctl restart soc-orchestrator.service
```

---

## Scenario 2: Living-off-the-Land Honeyport Probe (`HONEYPORT_SCAN`)

Simulates internal service discovery using native Bash socket descriptors when `nc` (`netcat`) is unavailable.

1. Connect via SSH as `marianela_recepcion` on `TCP/2222`.
2. Probe the RDP decoy port (`TCP/3389`) via `/dev/tcp/`:
   ```bash
   timeout 1 bash -c "</dev/tcp/127.0.0.1/3389"
   ```
3. **Expected Result:**
   - The passive TCP listener completes the 3-way handshake, closes the socket, and triggers containment.
   - The SSH session drops synchronously (`Connection to <VM_IP> closed by remote host.`).
   - A `HONEYPORT_SCAN` JSONL record is written to `/opt/clinica/logs/soc_actions.log` mapped to ISO `A.8.16`/`A.8.20` and NIST `DE.CM-01`/`RS.RP-01`.
   - Urgent push notification arrives on the configured `ntfy.sh` channel.

---

## Local Verification Without Root (Dry-Run Mode)

To inspect behavior safely in a local dev environment:

```bash
python3 -m unittest discover -s tests -v
```
