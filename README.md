# CRA Vulnerability Watchtower 🏰

[![CI](https://github.com/hashim-work-svg/cra-watchtower/actions/workflows/ci.yml/badge.svg)](https://github.com/hashim-work-svg/cra-watchtower/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20CGO_ENABLED%3D0-brightgreen.svg)](#installation)

> **Software Supply-Chain Audit, Actively Exploited CVE Matching, and Mandatory CRA Reporting Engine.**

---

## 1. Problem & Industry Evidence

The **EU Cyber Resilience Act ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847))** introduces sweeping cybersecurity obligations for manufacturers distributing hardware and software products with digital elements into the European Union:

* **Enforced Deadlines:** As of **11 September 2026**, manufacturers must notify ENISA and designated national CSIRTs within **24 hours** of becoming aware of an actively exploited vulnerability, followed by a detailed assessment at **72 hours** and a final report within **14 days**.
* **Massive Penalties:** Failure to meet core reporting requirements can trigger administrative fines up to **€15,000,000 or 2.5% of annual worldwide turnover**, whichever is higher.
* **The Supply-Chain Challenge:** Modern products embed hundreds of third-party open-source components. Without automated SBOM parsing, PURL canonicalization, and real-time correlation against exploited CVE databases (e.g., CISA KEV), meeting a 24-hour statutory reporting deadline is virtually impossible.

**`cra-watchtower`** solves this by automating SBOM ingestion, normalizing components into Package URLs, flagging actively exploited CVEs, tracking compliance countdown clocks, and generating pre-populated, audit-ready Markdown notifications.

---

## 2. Key Capabilities

* 📦 **Dual SBOM Ingestion:** Auto-detects and ingests both **OWASP CycloneDX** (v1.4, v1.5) and **Linux Foundation SPDX** (v2.2, v2.3) JSON specifications.
* 🏷️ **Canonical PURL Resolution:** Converts vendor-specific package declarations into standard Package URLs (`purl-spec`) using `packageurl-go`.
* ⚡ **Actively Exploited (KEV) Detection:** Correlates dependencies with public vulnerability databases (OSV.dev) and flags entries on the CISA Known Exploited Vulnerabilities catalog.
* ⏱️ **CRA Reporting Clock Tracker:** Computes exact countdown deadlines ($T_{24}$, $T_{72}$, $T_{14d}$) based on verified awareness time, tracking statuses (`ON TIME`, `DUE SOON`, `OVERDUE`).
* 📝 **Compliance Draft Generator:** Pre-populates Article 14 Early Warning, Notification, and Final Report Markdown documents with technical facts while highlighting sections requiring human legal sign-off.
* 🌐 **Static Single Binary (`CGO_ENABLED=0`):** Shipped as one self-contained, offline-capable static binary for Linux, macOS, and Windows.

---

## 3. Architecture Overview

```
[CycloneDX / SPDX JSON SBOM]
          │
          ▼
   ┌───────────────┐
   │ Auto-Detector │ ───► Identifies Format & Deserializes Schema
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │PURL Normalizer│ ───► Canonicalizes to pkg:<type>/<name>@<version>
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Vuln Matcher  │ ───► Queries OSV.dev and CISA KEV Offline Cache
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │  CRA Clock    │ ───► Calculates 24h, 72h, and 14d Article 14 Deadlines
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │Draft Generator│ ───► Pre-Fills Markdown Reports & Standalone HTML Dashboard
   └───────────────┘
```

---

## 4. Quickstart

### Ingest an SBOM:
```bash
# Ingest and display tabular summary
./cra-watchtower ingest fixtures/sample-cyclonedx.json

# Output as normalized JSON
./cra-watchtower ingest fixtures/sample-spdx.json --json
```

---

## 5. What `cra-watchtower` Does Not Do (Honest Limitations)

1. **No Automated Submission:** The tool **never automatically submits notifications** to ENISA's Single Reporting Platform or national CSIRTs. Submissions require human legal verification and formal corporate authorization.
2. **Awareness Trigger:** The legal trigger under Article 14 is the manufacturer's own awareness of an actively exploited flaw. CISA KEV matching provides an automated alert signal, but does not substitute for corporate risk determination.
3. **Not Legal Advice:** See notice below.

---

## 6. Regulatory & Legal Notice

> [!IMPORTANT]
> **Not Legal Advice:** This utility and its generated drafts are technical aids designed for engineering and compliance workflows. They do not constitute formal legal advice under Regulation (EU) 2024/2847. Organizations must consult qualified legal counsel to ensure compliance.

---

## 7. License

Distributed under the [MIT License](LICENSE). Copyright (c) 2026 Muhammad Hashim.
