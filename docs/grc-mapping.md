# GRC Alignment & Risk Traceability Matrix

This document links the technical deception and SOAR controls implemented in `soc_orchestrator.py` to a structured Governance, Risk, and Compliance (GRC) baseline modeled on:

- **ISO/IEC 27005:2022** — Risk identification, qualitative scoring (`Likelihood × Impact`), and treatment decisions.
- **ISO/IEC 27002:2022** — Reference security control selection (`A.5.18`, `A.8.16`, `A.8.20`).
- **NIST Cybersecurity Framework (CSF) 2.0** — Alignment with `Protect`, `Detect`, and `Respond` outcomes.

> **Scope Notice:** Risk ratings reflect the simulated *Centro Médico del Sur* baseline rather than a live clinical audit, and alignment does not represent formal ISO/NIST certification.

---

## 1. Asset Criticality Baseline (CIA Scale: 1 = Low, 2 = Medium, 3 = High)

| ID | Asset | C | I | D | Overall Criticality |
| :---: | :--- | :---: | :---: | :---: | :---: |
| **A01** | Electronic Health Records (EHR) | 3 | 3 | 3 | High |
| **A02** | Linux Application Server (`srv-clinica-core`) | 2 | 3 | 3 | High |
| **A03** | Patient Database | 3 | 3 | 3 | High |
| **A04** | Scheduling / Appointments System | 3 | 3 | 2 | High |
| **A05** | Administrative & Staff Credentials | 3 | 3 | 2 | High |
| **A06** | Backup Server | 3 | 3 | 3 | High |
| **A07** | Internal Corporate LAN | 3 | 3 | 3 | High |
| **A08** | Billing & Accounting System | 2 | 3 | 2 | High |
| **A09** | Firewall & Network Configuration | 3 | 3 | 3 | High |
| **A10** | Remote Administrative Access (VPN / SSH) | 3 | 3 | 2 | High |

---

## 2. Risk Register & Control Traceability

*Scoring scale:* Likelihood (`1–3`) × Impact (`1–3`). Risk levels: Very Low (`1`), Low (`2`), Medium (`3–4`), High (`6`), Very High (`9`). All risks `>= 4` require documented treatment.

| ID | Risk Scenario | Assets | L × I | Level | Selected Treatment / Control | Implementation Status |
| :---: | :--- | :--- | :---: | :---: | :--- | :--- |
| **R01** | Unauthorized remote access | A02, A10 | 2 × 3 = 6 | High | Restrict admin SSH to `TCP/2222` with key-based auth; deception complements preventive controls. | Partially implemented in lab |
| **R02** | Credential theft / misuse | A05, A10 | 2 × 3 = 6 | High | Enforce MFA, least privilege, and credential hygiene. | Proposed (Org control) |
| **R03** | Ransomware infection & lateral spread | A01–A03, A06–A07 | 2 × 3 = 6 | High | Endpoint protection, network segmentation, and recoverable backups; early deception tripwires. | Proposed; deception detection in lab |
| **R04** | Personal / clinical data exposure | A01, A03 | 2 × 3 = 6 | High | Access control + `auditd` monitoring on decoy credentials `.env`. | Partially implemented in lab |
| **R05** | Unverified backup restoration | A06 | 2 × 3 = 6 | High | Periodic backup integrity checks and restoration drills. | Proposed (Ops control) |
| **R06** | Insufficient internal event monitoring | A02, A07, A09–A10 | 3 × 2 = 6 | High | `auditd` honeytoken monitoring + `TCP/445` & `TCP/3389` honeyports via `soc_orchestrator.py` + JSONL ticketing. | **Implemented in lab** |
| **R07** | Delayed incident response | A02, A07, A10 | 3 × 2 = 6 | High | Automated PAM lockout + `pkill -KILL` + structured JSONL tickets + `ntfy.sh` push alerts. | **Automated containment implemented**; full SOP proposed |
| **R08** | Erroneous automated lockouts (false positives) | A05, A10 | 2 × 2 = 4 | Medium | Attribution validation, scanner allowlists, and documented manual account recovery (`scripts/recover_account.sh`). | Recovery runbook added; validation proposed |
| **R09** | Improper account revocation | A05, A10 | 2 × 2 = 4 | Medium | Standardized lockout & recovery workflow with forced credential rotation (`chage -d 0`). | Partially implemented |
| **R10** | Compromise of deception environment itself | Lab host | 2 × 3 = 6 | High | Segregated admin SSH, privilege-separation roadmap, and passive non-protocol honeyports. | Partially implemented in lab |

---

## 3. Telemetry-to-Framework Mapping (Emitted in JSONL Tickets)

| Detection Trigger | Description | ISO/IEC 27001/27002:2022 | NIST CSF 2.0 |
| :--- | :--- | :--- | :--- |
| `HONEYTOKEN_READ` | Kernel `auditd` hit (`honeytoken_acceso`) on decoy `.env` for monitored UID | `A.8.16` (Monitoring activities), `A.5.18` (Access rights) | `PR.AA-05` (Access permissions revoked), `RS.RP-01` (Incident Response) |
| `HONEYPORT_SCAN` | Unauthorized TCP handshake on decoy `SMB (445)` or `RDP (3389)` listener | `A.8.16` (Monitoring activities), `A.8.20` (Network security) | `DE.CM-01` (Network monitoring), `RS.RP-01` (Incident Response) |
