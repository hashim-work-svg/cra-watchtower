# Architecture: CRA Vulnerability Watchtower

`cra-watchtower` ingests product Software Bills of Materials (SBOMs), correlates components against public vulnerability feeds (OSV) and the CISA Known Exploited Vulnerabilities (KEV) catalog, monitors mandatory reporting deadlines, and produces audit-ready compliance drafts.

## Pipeline Architecture Diagram

```mermaid
flowchart TD
    subgraph Inputs["Input Sources"]
        CycloneDX["CycloneDX JSON (1.4 / 1.5)"]
        SPDX["SPDX JSON (2.2 / 2.3)"]
        Awareness["Awareness Timestamp\n(CLI Flag / Config)"]
    end

    subgraph Core["CRA Watchtower Engine (Static Go Binary)"]
        Detector["SBOM Detector & Parser\n(Auto-identifies CycloneDX vs SPDX)"]
        Normalizer["PURL Normalizer & Resolver\n(Converts components to canonical PURLs)"]
        
        subgraph DB["Vulnerability Cache & Matching"]
            VulnCache[("Local SQLite / JSON Cache\n(OSV.dev + CISA KEV Feed)")]
            Matcher["Vulnerability Matcher\n(Affects Version & Fix Analysis)"]
            KEVFlag["Actively Exploited Filter\n(Flags CISA KEV Candidates)"]
        end

        subgraph Compliance["CRA Article 14 Engine"]
            Clock["Reporting Clock Tracker\n(24h Early Warning, 72h Notice, 14d Final)"]
            DraftGen["Draft Generator\n(Pre-populates Markdown drafts)"]
            HTMLGen["HTML Dashboard Renderer\n(Single self-contained web report)"]
        end
    end

    subgraph Outputs["Compliance Deliverables"]
        Console["CLI Table Output"]
        EarlyDraft["24h Early Warning Draft (MD)"]
        NoticeDraft["72h Vulnerability Notice (MD)"]
        FinalDraft["14d Final Report (MD)"]
        Dashboard["Standalone HTML Dashboard"]
    end

    CycloneDX --> Detector
    SPDX --> Detector
    Detector --> Normalizer
    Normalizer --> Matcher
    VulnCache -.-> Matcher
    Matcher --> KEVFlag
    KEVFlag --> Clock
    Awareness --> Clock
    Clock --> DraftGen
    Clock --> HTMLGen
    Clock --> Console
    DraftGen --> EarlyDraft
    DraftGen --> NoticeDraft
    DraftGen --> FinalDraft
    HTMLGen --> Dashboard
```

## Architectural Components

1. **Format Ingestion & Detection:**
   The `internal/sbom` package scans the initial JSON structure without requiring pre-configuration. It identifies `bomFormat: "CycloneDX"` or `spdxVersion: "SPDX-..."` and deserializes into a unified component model.

2. **PURL Normalization (`internal/sbom/purl.go`):**
   Converts ad-hoc package declarations into strictly validated Package URLs (`pkg:<type>/<namespace>/<name>@<version>`). When PURLs are absent, canonical fallbacks are dynamically generated using ecosystem heuristics.

3. **Vulnerability Cache & Matching (`internal/vulndb` & `internal/matcher`):**
   Offline-first SQLite or cached JSON storage containing OSV vulnerability records and CISA KEV entries. Matches version constraints against component releases without requiring live network calls in production or test environments.

4. **Reporting Clock Tracker (`internal/clock`):**
   Maintains timezone-aware compliance clocks. Calculates exact deadlines:
   - **$T_{24}$:** Early warning to ENISA / CSIRT.
   - **$T_{72}$:** Full vulnerability notification.
   - **$T_{14d}$:** Final remediation summary.

5. **Draft & Dashboard Renderers (`internal/drafts` & `internal/report`):**
   Embeds Go HTML templates via `go:embed` to produce clean, single-page offline reports and pre-filled Markdown draft notifications with clear markers for required human inputs.
