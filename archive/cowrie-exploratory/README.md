# Exploratory Phase Archive: Cowrie SSH/Telnet Honeypot (ADR-001)

This directory preserves the initial Docker-based Cowrie honeypot configuration evaluated during the early exploratory phase of the project.

## Decision: Excluded from Definitive Architecture

Cowrie was **not** carried forward into the final *Assume Breach* architecture for two engineering reasons observed during Azure lab testing (`Standard_B1s` — 1 vCPU, 1 GB RAM, Debian 12):

1. **Threat Model Misalignment (Perimeter vs. Post-Breach):** Cowrie captures external automated SSH/Telnet brute-force noise from the Internet. The target risk scenario (*Centro Médico del Sur*) focuses on **post-compromise internal detection** after an adversary already holds legitimate credentials (e.g., via phishing).
2. **Resource Footprint on Constrained Hosts:** In laboratory measurements, running Cowrie via Docker consumed roughly **~200 MB of RAM** plus container runtime overhead, whereas the native Python + `auditd` orchestrator (`soc_orchestrator.py`) operated at **~10.6 MB of RAM** with fewer moving parts to maintain.

The definitive architecture replaces perimeter Cowrie with internal kernel-audited honeytokens (`auditd`) and lightweight TCP honeyports (`445`/`3389`) wired directly into automated PAM identity containment.
