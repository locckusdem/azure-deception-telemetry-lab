# Technical Architecture & Engineering Decisions

## 1. Threat Model & Operational Constraints

This architecture addresses **post-compromise detection and automated containment (*Assume Breach*)** for a resource-constrained small-to-medium healthcare environment (*Centro Médico del Sur* reference case).

- **Host Profile:** Azure `Standard_B1s` (1 vCPU, 1 GB RAM), Debian 12 (`srv-clinica-core`).
- **Administrative Plane:** SSH relocated to `TCP/2222` with key-based authentication (`<admin_user>` account), separated from the synthetic compromised user (`marianela_recepcion`, `UID 1001`).
- **Core Problem:** Traditional perimeter controls (firewall, AV) rarely trigger high-confidence alerts when an attacker authenticates with **valid stolen credentials** (e.g., via phishing) and operates using native OS binaries (*Living off the Land*).

## 2. Detection & SOAR Pipeline

1. **Kernel Honeytoken (`auditd`):**
   - Decoy file: `/opt/clinica/datos/pacientes_db_credenciales.env`
   - Rule: `-w /opt/clinica/datos/pacientes_db_credenciales.env -p rwa -k honeytoken_acceso`
   - `soc_orchestrator.py` tails `/var/log/audit/audit.log` (with inode/truncation rotation handling) and filters events matching both `honeytoken_acceso` and the numeric UID resolved via `pwd.getpwnam()`.
2. **Passive Internal Honeyports (`TCP/445` SMB, `TCP/3389` RDP):**
   - Lightweight TCP sockets complete the 3-way handshake without emulating full SMB/RDP stacks, immediately closing the connection and raising `HONEYPORT_SCAN`.
   - Captures native LotL probes (such as Bash `/dev/tcp/`) even when `nc` or `nmap` are absent.
3. **Burst Cooldown & Concurrency Guard:**
   - A `threading.Lock` + monotonic cooldown window (`SOC_COOLDOWN_SECONDS=5.0` by default) collapses syscall storms (e.g., `openat`/`read` bursts) into a single incident ticket.
4. **Automated PAM Containment:**
   - Locks the local identity and terminates all active sessions/processes belonging to the user.
5. **Forensic Ticketing & Push Alerting:**
   - Appends single-line JSONL records (`CMS-INC-YYYY-<epoch>`) to `/opt/clinica/logs/soc_actions.log` with ISO/IEC 27001:2022 and NIST CSF 2.0 mappings.
   - Dispatches urgent HTTP POST notifications to `ntfy.sh` when `SOC_NTFY_URL` is configured.

---

## 3. Architecture Decision Records (ADRs)

### ADR-001: Exclude Perimeter Cowrie Honeypot in Favor of Internal Deception
- **Context:** Initial exploratory tests deployed Cowrie in Docker (`archive/cowrie-exploratory/docker-compose.yml`).
- **Observed Trade-off:** Cowrie captured external Internet brute-force noise (~200 MB RAM overhead with Docker) rather than post-compromise internal lateral movement, whereas native Python + `auditd` used **~10.6 MB RAM** in the lab VM.
- **Decision:** Exclude Cowrie from the production-oriented PoC; retain its Compose manifest under `archive/cowrie-exploratory/` as an evaluated baseline.

### ADR-002: Replace `iptables` IP Blocking with PAM Identity Containment
- **Context:** Early honeyport prototypes blocked source IPs via `iptables -I INPUT -s <ip> -j DROP`.
- **Limitation:** Local loopback probes (`127.0.0.1`) or compromised accounts sharing a legitimate corporate workstation/NAT IP cannot be safely mitigated by IP drop rules alone—and IP blocking does not revoke an active interactive session authenticated over an existing socket.
- **Decision:** Pivot to host-level identity containment + `SIGKILL` session termination.

### ADR-003: Multi-Step PAM Lockout (Why `passwd -l` Alone Is Insufficient)
- **Finding:** During lab testing, locking the account password with `passwd -l` did **not** prevent subsequent logins using authorized SSH public keys (`~/.ssh/authorized_keys`).
- **Decision:** Chain four containment actions:
  1. `usermod --expiredate 1 <user>` — forces PAM account expiration check failure even for SSH key auth.
  2. `passwd -l <user>` — locks password authentication.
  3. `chsh -s /usr/sbin/nologin <user>` — revokes interactive shell access.
  4. `pkill -KILL -u <user>` — terminates active SSH sessions and child processes immediately.

---

## 4. Known PoC Limitations & Production Roadmap

| Area | Lab PoC Scope | Production Requirement |
| :--- | :--- | :--- |
| **Honeyport Attribution** | Single-host PoC attributes TCP probes to configured `SOC_TARGET_USER` because `socket.accept()` exposes peer IP/port rather than local process UID. | Correlate `/proc/net/tcp` + `/proc/<pid>/fd` for local sockets, or map source IP to workstation/user via DHCP + NAC/IAM logs and isolate via VLAN/firewall. |
| **Service Privileges** | `soc-orchestrator.service` runs as `root` to tail `/var/log/audit/audit.log`, bind `TCP/445`, and invoke PAM tools. | Drop privileges using `CAP_NET_BIND_SERVICE`, `adm`/`audit` log read group, and a tightly scoped `sudoers` policy (or separate unprivileged detector from privileged responder). |
| **Identity Scope** | Containment operates on local `/etc/passwd` / `/etc/shadow` accounts only. | Integrate with Active Directory / Microsoft Entra ID APIs to revoke federation tokens and disable directory accounts globally. |
| **False-Positive Handling** | Manual recovery via `scripts/recover_account.sh`. | Add human-in-the-loop approval or allowlist exceptions for authorized vulnerability scanners and administrative maintenance windows. |
