# CRA Vulnerability Watchtower 🏰

[![CI](https://github.com/hashim-work-svg/cra-watchtower/actions/workflows/ci.yml/badge.svg)](https://github.com/hashim-work-svg/cra-watchtower/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Static Binary](https://img.shields.io/badge/Binary-Static%20CGO_ENABLED%3D0-brightgreen.svg)](#installation)

> **Software Supply-Chain Audit, Actively Exploited CVE Matching, and Mandatory EU CRA Article 14 Compliance Engine.**

---

## 1. Implementation Status

| Feature | Status | Package | Description |
|---|---|---|---|
| **CycloneDX (1.4, 1.5, 1.6) Ingestion** | ✅ Production | `internal/sbom` | JSON parsing, bounded 10MB reader, supplier & manufacturer normalization |
| **SPDX (2.2, 2.3) Ingestion** | ✅ Production | `internal/sbom` | JSON parsing, externalRefs purl resolution, deduplication |
| **Canonical PURL Normalization** | ✅ Production | `internal/sbom` | RFC-compliant package URLs (`packageurl-go`), Maven/NPM namespace parsing |
| **Vulnerability DB (OSV & KEV)** | ✅ Production | `internal/vulndb` | Embedded offline fixtures (Log4Shell, Text4Shell, curl) + local cache sync |
| **Actively Exploited Matcher** | ✅ Production | `internal/matcher` | Version range comparison, CISA KEV correlation & candidate alert flag |
| **Article 14 Reporting Clock** | ✅ Production | `internal/clock` | Timezone-safe UTC calculations: 24h Early Warning, 72h Notification, 14d Final Report |
| **Notification Draft Generator** | ✅ Production | `internal/drafts` | 3 Markdown notification drafts (Stages 1, 2, 3) clearly highlighting required human input |
| **Standalone HTML Dashboard** | ✅ Production | `internal/report` | Zero-dependency responsive HTML report with embedded CSS and Markdown summary |
| **SBOM Diff Comparison** | ✅ Production | `internal/diff` | Component and vulnerability delta comparison across product versions |
| **Zero-Install Demo** | ✅ Production | `internal/demo` | `cra-watchtower demo` runs fully offline on embedded fixtures |

---

## 2. Problem & Regulatory Context

The **EU Cyber Resilience Act ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847))** introduces strict cybersecurity obligations for manufacturers distributing hardware and software products with digital elements into the European Union:

* **Enforced Statutory Deadlines:** As of **11 September 2026** (Article 14 application date), manufacturers must notify ENISA and designated national CSIRTs:
  1. **Stage 1 (Early Warning):** Within **24 hours** of becoming aware of an actively exploited vulnerability.
  2. **Stage 2 (Vulnerability Notification):** Within **72 hours** of becoming aware, including sensitivity and initial mitigations.
  3. **Stage 3 (Final Report):** No later than **14 days after a corrective or mitigating measure becomes available** (or at most 1 month for severe incidents).
* **Significant Penalties:** Non-compliance with Article 14 reporting requirements can trigger administrative fines up to **€15,000,000 or 2.5% of annual worldwide turnover**, whichever is higher (Article 64(2)).
* **The Supply-Chain Challenge:** Modern products embed hundreds of third-party open-source components. Without automated SBOM parsing, PURL canonicalization, and real-time correlation against exploited CVE databases (e.g., CISA KEV), meeting a 24-hour statutory reporting deadline is virtually impossible.

**`cra-watchtower`** automates this pipeline: ingests SBOMs, normalizes components to Package URLs, flags actively exploited CVEs, tracks compliance countdown clocks, and generates pre-populated, audit-ready Markdown notifications.

---

## 3. Architecture

```
[CycloneDX / SPDX JSON SBOM]
          │
          ▼
   ┌───────────────┐
   │ Auto-Detector │ ───► Identifies Format & Validates Specification Version
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │PURL Normalizer│ ───► Canonicalizes to pkg:<type>/<namespace>/<name>@<version>
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Vuln Matcher  │ ───► Queries OSV.dev & CISA KEV Offline Catalog
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │ Article 14    │ ───► Computes 24h Early Warning, 72h Notification,
   │  Clock        │      and 14d Post-Mitigation Final Deadlines (UTC)
   └───────┬───────┘
           ▼
   ┌───────────────┐
   │Draft Generator│ ───► Produces Stage 1/2/3 Markdown Drafts & HTML Dashboard
   └───────────────┘
```

---

## 4. Installation

### Option A: Install via Go toolchain
```bash
go install github.com/hashim-work-svg/cra-watchtower/cmd/cra-watchtower@latest
```

### Option B: Build from Source (Static Binary)
```bash
git clone https://github.com/hashim-work-svg/cra-watchtower.git
cd cra-watchtower
make build-static
```

### Option C: Download Pre-built Release
Download statically linked binaries for Linux, macOS, and Windows from GitHub Releases with SHA-256 checksums.

---

## 5. Quickstart & Zero-Install Demo

### Run Zero-Install Interactive Demo:
Run immediately with no local setup, external database, or network connectivity:
```bash
cra-watchtower demo
```

### Ingest and Inspect an SBOM:
```bash
# Tabular component view
cra-watchtower ingest fixtures/sample-cyclonedx.json

# Normalized JSON output
cra-watchtower ingest fixtures/sample-spdx.json --json
```

### Match Vulnerabilities and Check KEV Status:
```bash
# Scan SBOM against vulnerability database
cra-watchtower match fixtures/sample-cyclonedx.json

# CI Gate: Fail build if any actively exploited vulnerability is detected
cra-watchtower match fixtures/sample-cyclonedx.json --fail-on-exploited
```

### Track Article 14 Countdown Clocks:
```bash
cra-watchtower clock --aware "2026-10-24T10:00:00Z" --mitigated "2026-10-25T12:00:00Z"
```

### Generate Regulatory Notification Drafts:
```bash
cra-watchtower drafts fixtures/sample-cyclonedx.json --cve CVE-2021-44228 --aware "2026-10-24T10:00:00Z" --output-dir ./drafts
```

### Generate Standalone HTML Compliance Dashboard:
```bash
cra-watchtower report fixtures/sample-cyclonedx.json --aware "2026-10-24T10:00:00Z" --output report.html
```

---

## 6. What `cra-watchtower` Does Not Do (Honest Limitations)

1. **No Automated Regulatory Submission:** The tool **never automatically submits notifications** to ENISA's Single Reporting Platform or national CSIRTs. Submissions require human legal verification and formal corporate authorization.
2. **Awareness Trigger:** The statutory trigger under CRA Article 14 is the manufacturer's own awareness of an actively exploited flaw. CISA KEV matching provides an automated alert signal, but does not substitute for corporate risk determination.
3. **Severe Incidents:** Article 14 also covers severe incidents impacting product security; this tool focuses specifically on the actively exploited vulnerability track.
4. **Not Legal Advice:** See notice below.

---

## 7. Regulatory & Legal Notice

> [!IMPORTANT]
> **Not Legal Advice:** This utility and its generated drafts are technical aids designed for engineering and compliance workflows. They do not constitute formal legal advice under Regulation (EU) 2024/2847. Organizations must consult qualified legal counsel to ensure compliance. Official guidance is published by the [European Commission](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) and [ENISA](https://www.enisa.europa.eu/).

---

## 8. License & Contributors

Distributed under the [MIT License](LICENSE).

Authored by **Muhammad Hashim** ([@hashim-work-svg](https://github.com/hashim-work-svg)) with contributions from [@Hashim-svg](https://github.com/Hashim-svg).
