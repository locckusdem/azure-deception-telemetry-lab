#!/usr/bin/env python3
"""
SOC Orchestrator - Deception Telemetry & Automated Incident Response (SOAR)

Monitors kernel-level auditd events for honeytoken access and passive TCP
honeyport probes under an Assume Breach threat model. Coordinates PAM-level
identity containment, structured JSONL forensic ticketing (mapped to ISO/IEC
27001:2022 and NIST CSF 2.0), and real-time push notifications via ntfy.sh.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import pwd
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Callable
import urllib.request

LOGGER = logging.getLogger("soc_orchestrator")


def _parse_bool(raw: str | None, default: bool = False) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_honeyports(spec: str) -> dict[int, str]:
    """Parse comma-separated 'port:service' pairs (e.g. '445:SMB,3389:RDP')."""
    ports: dict[int, str] = {}
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"Invalid honeyport entry '{item}'; expected PORT:SERVICE")
        port_str, service = item.split(":", 1)
        port = int(port_str.strip())
        if not (1 <= port <= 65535):
            raise ValueError(f"Port out of range: {port}")
        ports[port] = service.strip()
    return ports


@dataclass(frozen=True)
class OrchestratorConfig:
    """Runtime configuration loaded from environment variables and CLI flags."""

    target_user: str = "marianela_recepcion"
    honeytoken_path: str = "/opt/clinica/datos/pacientes_db_credenciales.env"
    audit_log_path: str = "/var/log/audit/audit.log"
    audit_key: str = "honeytoken_acceso"
    forensic_log_path: str = "/opt/clinica/logs/soc_actions.log"
    honeyports: dict[int, str] = field(default_factory=lambda: {445: "SMB", 3389: "RDP"})
    bind_host: str = "0.0.0.0"
    ntfy_url: str = ""
    cooldown_seconds: float = 5.0
    dry_run: bool = False
    enable_honeyports: bool = True

    @classmethod
    def from_env(cls) -> "OrchestratorConfig":
        """Build configuration from SOC_* environment variables."""
        ports_raw = os.getenv("SOC_HONEYPORTS", "445:SMB,3389:RDP")
        return cls(
            target_user=os.getenv("SOC_TARGET_USER", "marianela_recepcion"),
            honeytoken_path=os.getenv(
                "SOC_HONEYTOKEN_PATH", "/opt/clinica/datos/pacientes_db_credenciales.env"
            ),
            audit_log_path=os.getenv("SOC_AUDIT_LOG_PATH", "/var/log/audit/audit.log"),
            audit_key=os.getenv("SOC_AUDIT_KEY", "honeytoken_acceso"),
            forensic_log_path=os.getenv(
                "SOC_FORENSIC_LOG_PATH", "/opt/clinica/logs/soc_actions.log"
            ),
            honeyports=parse_honeyports(ports_raw),
            bind_host=os.getenv("SOC_BIND_HOST", "0.0.0.0"),
            ntfy_url=os.getenv("SOC_NTFY_URL", "").strip(),
            cooldown_seconds=float(os.getenv("SOC_COOLDOWN_SECONDS", "5.0")),
            dry_run=_parse_bool(os.getenv("SOC_DRY_RUN"), default=False),
        )


def resolve_target_uid(username: str) -> int:
    """Resolve the numeric POSIX UID for the monitored account."""
    return pwd.getpwnam(username).pw_uid


def matches_audit_event(line: str, audit_key: str, target_uid: int) -> bool:
    """Return True when an audit.log record matches both key and exact UID."""
    if audit_key not in line:
        return False
    return re.search(rf"\buid={target_uid}\b", line) is not None


def build_framework_mapping(trigger: str) -> dict[str, str]:
    """Map technical detection triggers to ISO/IEC 27001:2022 and NIST CSF 2.0."""
    if trigger == "HONEYTOKEN_READ":
        return {
            "iso27001_2022": "A.8.16 (Monitoring activities), A.5.18 (Access rights)",
            "nist_csf_2": "PR.AA-05 (Access permissions revoked), RS.RP-01 (Incident Response)",
        }
    return {
        "iso27001_2022": "A.8.16 (Monitoring activities), A.8.20 (Network security)",
        "nist_csf_2": "DE.CM-01 (Network monitoring), RS.RP-01 (Incident Response)",
    }


def execute_pam_containment(
    username: str,
    dry_run: bool = False,
    runner: Callable[..., Any] = subprocess.run,
) -> list[str]:
    """
    Execute Linux PAM containment against a compromised local account.

    Note: `passwd -l` alone does not block SSH public-key authentication;
    combining account expiration (`usermod --expiredate 1`), nologin shell,
    and `pkill -KILL` enforces immediate lockout and session termination.
    """
    commands = [
        ["usermod", "--expiredate", "1", username],
        ["passwd", "-l", username],
        ["chsh", "-s", "/usr/sbin/nologin", username],
        ["pkill", "-KILL", "-u", username],
    ]

    if dry_run:
        LOGGER.info("[DRY-RUN] Skipping destructive PAM containment for '%s'", username)
    else:
        for cmd in commands:
            runner(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return [
        f"Account expired & locked: usermod/passwd {username}",
        f"Shell revoked: chsh -s /usr/sbin/nologin {username}",
        f"Active sessions terminated: pkill -KILL -u {username}",
    ]


def build_incident_record(
    ticket_id: str,
    timestamp_utc: str,
    username: str,
    trigger: str,
    details: str,
    soar_actions: list[str],
    dry_run: bool = False,
) -> dict[str, Any]:
    """Build a SIEM/ITSM-compatible JSON incident ticket."""
    record: dict[str, Any] = {
        "ticket_id": ticket_id,
        "timestamp_utc": timestamp_utc,
        "incident": "INSIDER_OR_COMPROMISED_ACCOUNT",
        "compromised_user": username,
        "detection_trigger": trigger,
        "details": details,
        "soar_actions": soar_actions,
        "framework_mapping": build_framework_mapping(trigger),
    }
    if dry_run:
        record["dry_run"] = True
    return record


def write_forensic_ticket(forensic_log_path: str, record: dict[str, Any]) -> None:
    """Append a single-line JSONL incident ticket to the forensic log."""
    parent = os.path.dirname(os.path.abspath(forensic_log_path))
    os.makedirs(parent, exist_ok=True)
    with open(forensic_log_path, "a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def send_ntfy_alert(
    ntfy_url: str,
    ticket_id: str,
    username: str,
    uid: int,
    trigger: str,
    details: str,
    dry_run: bool = False,
    urlopen_fn: Callable[..., Any] = urllib.request.urlopen,
) -> bool:
    """Send an urgent push notification to the IT/SecOps ntfy.sh channel."""
    if not ntfy_url:
        LOGGER.debug("SOC_NTFY_URL not configured; skipping external push alert.")
        return False

    if dry_run:
        LOGGER.info("[DRY-RUN] Would POST alert for %s to %s", ticket_id, ntfy_url)
        return False

    title = f"[CMS-SOC] Automated Containment: {username}"
    message = (
        "Security Alert: Unauthorized deception trigger detected.\n"
        f"- Ticket: {ticket_id}\n"
        f"- Compromised Account: {username} (UID: {uid})\n"
        f"- Deception Trigger: {trigger}\n"
        f"- Details: {details}\n\n"
        "SOAR Action: Account locked at PAM layer and active sessions terminated.\n"
        "Status: Pending credential rotation and incident remediation."
    )

    req = urllib.request.Request(
        ntfy_url,
        data=message.encode("utf-8"),
        method="POST",
        headers={
            "Title": title,
            "Priority": "urgent",
            "Tags": "rotating_light,lock,shield",
        },
    )
    try:
        with urlopen_fn(req, timeout=5):
            return True
    except Exception as exc:  # pragma: no cover - defensive network boundary
        LOGGER.warning("Failed to deliver ntfy.sh alert for %s: %s", ticket_id, exc)
        return False


class SOCOrchestrator:
    """Coordinates deception listeners, burst suppression, and SOAR containment."""

    def __init__(
        self,
        config: OrchestratorConfig,
        target_uid: int | None = None,
        clock: Callable[[], float] = time.monotonic,
        runner: Callable[..., Any] = subprocess.run,
        urlopen_fn: Callable[..., Any] = urllib.request.urlopen,
    ) -> None:
        self.config = config
        self.target_uid = (
            target_uid if target_uid is not None else resolve_target_uid(config.target_user)
        )
        self._clock = clock
        self._runner = runner
        self._urlopen = urlopen_fn
        self._lock = threading.Lock()
        self._last_containment_ts: float | None = None
        self.stop_event = threading.Event()

    def handle_trigger(self, trigger: str, details: str) -> dict[str, Any] | None:
        """
        Process a detection event under cooldown protection.

        Returns the created incident ticket dictionary, or None if suppressed
        by the active burst cooldown window.
        """
        with self._lock:
            now_mono = self._clock()
            if (
                self._last_containment_ts is not None
                and (now_mono - self._last_containment_ts) < self.config.cooldown_seconds
            ):
                LOGGER.debug("Suppressed duplicate trigger '%s' inside cooldown window.", trigger)
                return None
            self._last_containment_ts = now_mono

            utc_now = datetime.now(timezone.utc)
            ticket_id = f"CMS-INC-{utc_now.year}-{int(utc_now.timestamp())}"
            timestamp_utc = utc_now.isoformat()

            soar_actions = execute_pam_containment(
                username=self.config.target_user,
                dry_run=self.config.dry_run,
                runner=self._runner,
            )
            record = build_incident_record(
                ticket_id=ticket_id,
                timestamp_utc=timestamp_utc,
                username=self.config.target_user,
                trigger=trigger,
                details=details,
                soar_actions=soar_actions,
                dry_run=self.config.dry_run,
            )
            write_forensic_ticket(self.config.forensic_log_path, record)
            send_ntfy_alert(
                ntfy_url=self.config.ntfy_url,
                ticket_id=ticket_id,
                username=self.config.target_user,
                uid=self.target_uid,
                trigger=trigger,
                details=details,
                dry_run=self.config.dry_run,
                urlopen_fn=self._urlopen,
            )
            LOGGER.warning(
                "Incident %s (%s) processed for user=%s uid=%d",
                ticket_id,
                trigger,
                self.config.target_user,
                self.target_uid,
            )
            return record

    def monitor_audit_log(self, start_at_end: bool = True) -> None:
        """Tail audit.log with rotation handling and trigger on matching honeytoken events."""
        path = self.config.audit_log_path
        while not self.stop_event.is_set() and not os.path.exists(path):
            self.stop_event.wait(0.5)

        if self.stop_event.is_set():
            return

        current_inode = os.stat(path).st_ino
        file_obj = open(path, "r", encoding="utf-8", errors="ignore")
        if start_at_end:
            file_obj.seek(0, os.SEEK_END)

        try:
            while not self.stop_event.is_set():
                line = file_obj.readline()
                if line:
                    if matches_audit_event(line, self.config.audit_key, self.target_uid):
                        details = f"Unauthorized access to decoy file {self.config.honeytoken_path}"
                        self.handle_trigger(trigger="HONEYTOKEN_READ", details=details)
                    continue

                # Detect log rotation or truncation
                try:
                    stat_info = os.stat(path)
                    if stat_info.st_ino != current_inode or stat_info.st_size < file_obj.tell():
                        file_obj.close()
                        file_obj = open(path, "r", encoding="utf-8", errors="ignore")
                        current_inode = stat_info.st_ino
                except FileNotFoundError:
                    pass

                self.stop_event.wait(0.1)
        finally:
            file_obj.close()

    def serve_honeyport(
        self,
        port: int,
        service_name: str,
        ready_callback: Callable[[int], None] | None = None,
    ) -> None:
        """Listen on a passive TCP socket, complete 3-way handshake, and trigger SOAR."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(0.5)
        try:
            srv.bind((self.config.bind_host, port))
            srv.listen(5)
            bound_port = srv.getsockname()[1]
            LOGGER.info(
                "Honeyport active on %s:%d (%s)",
                self.config.bind_host,
                bound_port,
                service_name,
            )
            if ready_callback is not None:
                ready_callback(bound_port)

            while not self.stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                except TimeoutError:
                    continue
                try:
                    peer_ip = addr[0]
                    details = f"Internal probe detected on TCP/{bound_port} ({service_name}) from {peer_ip}"
                finally:
                    conn.close()
                self.handle_trigger(trigger="HONEYPORT_SCAN", details=details)
        finally:
            srv.close()

    def run(self) -> None:
        """Start auditd monitor and honeyport threads until stop_event is set."""
        LOGGER.info(
            "Starting SOC Orchestrator | target_user=%s uid=%d dry_run=%s",
            self.config.target_user,
            self.target_uid,
            self.config.dry_run,
        )
        threads: list[threading.Thread] = [
            threading.Thread(
                target=self.monitor_audit_log,
                name="auditd-honeytoken-watcher",
                daemon=True,
            )
        ]

        if self.config.enable_honeyports:
            for port, svc in self.config.honeyports.items():
                threads.append(
                    threading.Thread(
                        target=self.serve_honeyport,
                        args=(port, svc),
                        name=f"honeyport-{port}",
                        daemon=True,
                    )
                )

        for thread in threads:
            thread.start()

        while not self.stop_event.is_set():
            self.stop_event.wait(0.5)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments overriding environment configuration."""
    parser = argparse.ArgumentParser(
        description="Assume Breach SOC Orchestrator (auditd honeytoken + TCP honeyports)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log detections and write JSON tickets without running PAM lockout or ntfy POST",
    )
    parser.add_argument(
        "--no-honeyports",
        action="store_true",
        help="Disable TCP honeyport listeners (useful when running without privileged port caps)",
    )
    parser.add_argument("--target-user", help="Override SOC_TARGET_USER")
    parser.add_argument("--audit-log", help="Override SOC_AUDIT_LOG_PATH")
    parser.add_argument("--forensic-log", help="Override SOC_FORENSIC_LOG_PATH")
    parser.add_argument("--ntfy-url", help="Override SOC_NTFY_URL")
    parser.add_argument("--log-level", default="INFO", help="Logging verbosity (default: INFO)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for systemd and interactive execution."""
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    base = OrchestratorConfig.from_env()
    config = OrchestratorConfig(
        target_user=args.target_user or base.target_user,
        honeytoken_path=base.honeytoken_path,
        audit_log_path=args.audit_log or base.audit_log_path,
        audit_key=base.audit_key,
        forensic_log_path=args.forensic_log or base.forensic_log_path,
        honeyports=base.honeyports,
        bind_host=base.bind_host,
        ntfy_url=args.ntfy_url if args.ntfy_url is not None else base.ntfy_url,
        cooldown_seconds=base.cooldown_seconds,
        dry_run=args.dry_run or base.dry_run,
        enable_honeyports=not args.no_honeyports,
    )

    try:
        orchestrator = SOCOrchestrator(config)
    except KeyError:
        LOGGER.error("Target user '%s' does not exist on this system.", config.target_user)
        return 1

    def _shutdown_handler(signum: int, _frame: Any) -> None:
        LOGGER.info("Received signal %d; shutting down orchestrator.", signum)
        orchestrator.stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    try:
        orchestrator.run()
    except PermissionError as exc:
        LOGGER.error("Insufficient privileges to bind honeyport or read audit log: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
