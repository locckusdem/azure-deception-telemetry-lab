"""Unit and socket integration tests for src/soc_orchestrator.py."""

from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
import time
import unittest

from src.soc_orchestrator import (
    OrchestratorConfig,
    SOCOrchestrator,
    build_framework_mapping,
    matches_audit_event,
    parse_honeyports,
)


class _DummyResponse:
    def __enter__(self) -> "_DummyResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class TestParsingAndMapping(unittest.TestCase):
    def test_parse_honeyports_valid(self) -> None:
        self.assertEqual(parse_honeyports("445:SMB, 3389:RDP"), {445: "SMB", 3389: "RDP"})

    def test_parse_honeyports_rejects_malformed(self) -> None:
        with self.assertRaises(ValueError):
            parse_honeyports("445")
        with self.assertRaises(ValueError):
            parse_honeyports("70000:BAD")

    def test_matches_audit_event_respects_uid_word_boundary(self) -> None:
        matching = (
            'type=SYSCALL msg=audit(1730150697.102:412): arch=c000003e syscall=257 '
            'success=yes exit=3 auid=1001 uid=1001 gid=1001 key="honeytoken_acceso"'
        )
        wrong_uid_prefix = (
            'type=SYSCALL msg=audit(1730150697.102:413): uid=10010 key="honeytoken_acceso"'
        )
        wrong_key = 'type=SYSCALL msg=audit(1730150697.102:414): uid=1001 key="other_rule"'

        self.assertTrue(matches_audit_event(matching, "honeytoken_acceso", 1001))
        self.assertFalse(matches_audit_event(wrong_uid_prefix, "honeytoken_acceso", 1001))
        self.assertFalse(matches_audit_event(wrong_key, "honeytoken_acceso", 1001))

    def test_framework_mapping_by_trigger(self) -> None:
        token_map = build_framework_mapping("HONEYTOKEN_READ")
        port_map = build_framework_mapping("HONEYPORT_SCAN")

        self.assertIn("A.5.18", token_map["iso27001_2022"])
        self.assertIn("PR.AA-05", token_map["nist_csf_2"])
        self.assertIn("A.8.20", port_map["iso27001_2022"])
        self.assertIn("DE.CM-01", port_map["nist_csf_2"])


class TestSOCOrchestrator(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.forensic_log = os.path.join(self.tmpdir.name, "soc_actions.log")
        self.audit_log = os.path.join(self.tmpdir.name, "audit.log")

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_active_containment_executes_pam_commands_writes_jsonl_and_posts_ntfy(self) -> None:
        executed_cmds: list[list[str]] = []
        sent_requests: list[object] = []

        def fake_runner(cmd: list[str], **_kwargs: object) -> None:
            executed_cmds.append(cmd)

        def fake_urlopen(req: object, timeout: float = 5) -> _DummyResponse:
            sent_requests.append((req, timeout))
            return _DummyResponse()

        cfg = OrchestratorConfig(
            target_user="marianela_recepcion",
            forensic_log_path=self.forensic_log,
            audit_log_path=self.audit_log,
            ntfy_url="https://ntfy.sh/test-topic",
            dry_run=False,
        )
        orch = SOCOrchestrator(
            cfg,
            target_uid=1001,
            clock=lambda: 100.0,
            runner=fake_runner,
            urlopen_fn=fake_urlopen,
        )

        record = orch.handle_trigger(
            "HONEYTOKEN_READ",
            "Unauthorized access to decoy file /opt/clinica/datos/pacientes_db_credenciales.env",
        )

        self.assertIsNotNone(record)
        assert record is not None
        self.assertTrue(record["ticket_id"].startswith("CMS-INC-"))
        self.assertEqual(record["compromised_user"], "marianela_recepcion")
        self.assertEqual(record["detection_trigger"], "HONEYTOKEN_READ")
        self.assertNotIn("dry_run", record)

        self.assertEqual(
            executed_cmds,
            [
                ["usermod", "--expiredate", "1", "marianela_recepcion"],
                ["passwd", "-l", "marianela_recepcion"],
                ["chsh", "-s", "/usr/sbin/nologin", "marianela_recepcion"],
                ["pkill", "-KILL", "-u", "marianela_recepcion"],
            ],
        )

        with open(self.forensic_log, "r", encoding="utf-8") as fh:
            persisted = [json.loads(line) for line in fh]
        self.assertEqual(len(persisted), 1)
        self.assertEqual(persisted[0]["ticket_id"], record["ticket_id"])

        self.assertEqual(len(sent_requests), 1)
        req, timeout = sent_requests[0]
        self.assertEqual(timeout, 5)
        self.assertEqual(req.full_url, "https://ntfy.sh/test-topic")
        self.assertEqual(req.get_method(), "POST")
        self.assertIn("HONEYTOKEN_READ", req.data.decode("utf-8"))

    def test_dry_run_skips_destructive_commands_and_network_calls(self) -> None:
        executed_cmds: list[list[str]] = []
        sent_requests: list[object] = []

        cfg = OrchestratorConfig(
            target_user="marianela_recepcion",
            forensic_log_path=self.forensic_log,
            ntfy_url="https://ntfy.sh/test-topic",
            dry_run=True,
        )
        orch = SOCOrchestrator(
            cfg,
            target_uid=1001,
            clock=lambda: 100.0,
            runner=lambda cmd, **_kw: executed_cmds.append(cmd),
            urlopen_fn=lambda req, **_kw: sent_requests.append(req),
        )

        record = orch.handle_trigger("HONEYPORT_SCAN", "Probe on TCP/3389")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertTrue(record.get("dry_run"))
        self.assertEqual(executed_cmds, [])
        self.assertEqual(sent_requests, [])

    def test_cooldown_suppresses_burst_triggers(self) -> None:
        now = [10.0]
        cfg = OrchestratorConfig(
            forensic_log_path=self.forensic_log,
            cooldown_seconds=5.0,
            dry_run=True,
        )
        orch = SOCOrchestrator(cfg, target_uid=1001, clock=lambda: now[0])

        first = orch.handle_trigger("HONEYTOKEN_READ", "first syscall")
        now[0] = 12.0
        suppressed = orch.handle_trigger("HONEYTOKEN_READ", "burst syscall")
        now[0] = 16.0
        second = orch.handle_trigger("HONEYTOKEN_READ", "after cooldown")

        self.assertIsNotNone(first)
        self.assertIsNone(suppressed)
        self.assertIsNotNone(second)

    def test_audit_log_watcher_detects_appended_honeytoken_line(self) -> None:
        with open(self.audit_log, "w", encoding="utf-8") as fh:
            fh.write("type=DAEMON_START msg=audit(1:1): op=start\n")

        cfg = OrchestratorConfig(
            target_user="marianela_recepcion",
            audit_log_path=self.audit_log,
            forensic_log_path=self.forensic_log,
            dry_run=True,
        )
        orch = SOCOrchestrator(cfg, target_uid=1001)

        watcher = threading.Thread(
            target=orch.monitor_audit_log,
            kwargs={"start_at_end": True},
            daemon=True,
        )
        watcher.start()
        try:
            time.sleep(0.15)
            with open(self.audit_log, "a", encoding="utf-8") as fh:
                fh.write('type=SYSCALL uid=1001 key="honeytoken_acceso"\n')
                fh.flush()

            deadline = time.monotonic() + 2.0
            while not os.path.exists(self.forensic_log) and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            orch.stop_event.set()
            watcher.join(timeout=2.0)

        self.assertTrue(os.path.exists(self.forensic_log))
        with open(self.forensic_log, "r", encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["detection_trigger"], "HONEYTOKEN_READ")

    def test_ephemeral_honeyport_listener_detects_tcp_probe(self) -> None:
        cfg = OrchestratorConfig(
            target_user="marianela_recepcion",
            bind_host="127.0.0.1",
            forensic_log_path=self.forensic_log,
            dry_run=True,
        )
        orch = SOCOrchestrator(cfg, target_uid=1001)
        bound_port: list[int] = []
        ready = threading.Event()

        def on_ready(port: int) -> None:
            bound_port.append(port)
            ready.set()

        listener = threading.Thread(
            target=orch.serve_honeyport,
            args=(0, "RDP", on_ready),
            daemon=True,
        )
        listener.start()
        try:
            self.assertTrue(ready.wait(timeout=2.0))
            with socket.create_connection(("127.0.0.1", bound_port[0]), timeout=2.0):
                pass

            deadline = time.monotonic() + 2.0
            while not os.path.exists(self.forensic_log) and time.monotonic() < deadline:
                time.sleep(0.05)
        finally:
            orch.stop_event.set()
            listener.join(timeout=2.0)

        self.assertTrue(os.path.exists(self.forensic_log))
        with open(self.forensic_log, "r", encoding="utf-8") as fh:
            records = [json.loads(line) for line in fh]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["detection_trigger"], "HONEYPORT_SCAN")
        self.assertIn(f"TCP/{bound_port[0]} (RDP)", records[0]["details"])


if __name__ == "__main__":
    unittest.main()
