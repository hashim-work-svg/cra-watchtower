# Architecture Decision Records (ADRs) - CRA Vulnerability Watchtower

## ADR-0001: Pure-Go Static Single-Binary Architecture (CGO_ENABLED=0)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Security engineers and compliance officers must be able to audit product SBOMs directly on build machines, CI/CD runners, and offline air-gapped workstations without installing external runtimes or C dependencies.
* **Decision:**
  Compile all binaries with `CGO_ENABLED=0`. Back local vulnerability and deadline caches with pure-Go SQLite (`modernc.org/sqlite`) or embedded JSON fixtures.
* **Consequences:**
  Zero external library requirements. Static executables run on Linux (amd64, arm64), macOS (amd64, arm64), and Windows (amd64).

---

## ADR-0002: Dual-Standard SBOM Ingestion (CycloneDX & SPDX)
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Enterprise supply chains use both OWASP CycloneDX (favored in application security) and Linux Foundation SPDX (favored in open-source compliance and licensing).
* **Decision:**
  Implement auto-detecting ingestion that reads both CycloneDX JSON (1.4 / 1.5) and SPDX JSON (2.2 / 2.3), converting both into a single internal `Component` structure.
* **Consequences:**
  Users do not need to specify CLI flags or convert SBOM formats prior to analysis.

---

## ADR-0003: Canonical Package URL (PURL) as Universal Component Identity
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  Correlating components against disparate databases (OSV.dev, CISA KEV, NVD) requires an unambiguous identifier across package ecosystems (Maven, npm, PyPI, Go, Generic).
* **Decision:**
  Adopt the Package URL standard (`purl-spec`, RFC draft) via `github.com/package-url/packageurl-go` as the core primary key for all component matching and vulnerability queries.
* **Consequences:**
  Ensures precision matching and eliminates string-based naming collisions across ecosystems.

---

## ADR-0004: Offline-First Fixture Caching for Verification
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  CI/CD pipelines and unit test suites may operate in sandboxed environments with limited or no outbound internet access.
* **Decision:**
  Decouple the matching and clock logic from live HTTP network calls. Provide embedded and cached test fixtures for OSV and CISA KEV feeds so all unit and end-to-end tests run 100% offline.
* **Consequences:**
  Fast, deterministic, and hermetic tests that never fail due to upstream API rate limits or network downtime.

---

## ADR-0005: Separation of Technical Drafting from Legal Advice
* **Date:** 2026-10-24
* **Status:** Accepted
* **Context:**
  EU Cyber Resilience Act non-compliance carries severe administrative penalties (up to €15M or 2.5% global turnover). Automated tools must not mislead users into believing tool execution satisfies legal compliance.
* **Decision:**
  Clearly demarcate auto-filled technical facts from sections requiring human review. Include mandatory "NOT LEGAL ADVICE" disclaimers on every report and document output.
* **Consequences:**
  Clear accountability and legal hygiene for enterprise users.
