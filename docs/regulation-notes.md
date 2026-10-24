# EU Cyber Resilience Act (CRA): Regulatory Reference & Obligations

## 1. Regulatory Context

The **EU Cyber Resilience Act** ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2847)) establishes harmonized cybersecurity standards for "products with digital elements" sold across the European Single Market.

### Critical Phase-in Dates:
* **11 September 2026:** Mandatory vulnerability and security incident reporting obligations enter into force (Article 14).
* **11 December 2027:** Full technical requirements—including mandatory machine-readable Software Bills of Materials (SBOMs), essential security requirements, and CE marking—apply.

---

## 2. Article 14 Reporting Windows (Vulnerabilities)

When a manufacturer becomes aware of an **actively exploited vulnerability** affecting a product with digital elements, strict mandatory reporting stages trigger:

1. **Stage 1 — Early Warning Notification (Within 24 Hours):**
   * *Trigger:* Manufacturer becoming aware of active exploitation in the wild.
   * *Recipient:* The European Union Agency for Cybersecurity (ENISA) via the Single Reporting Platform (SRP) and the designated Computer Security Incident Response Team (CSIRT).
   * *Content:* Preliminary indicator of exploitation, suspect CVE/vulnerability identifier, and immediate risk to other users.

2. **Stage 2 — Vulnerability Notification (Within 72 Hours):**
   * *Content:* Detailed vulnerability assessment, affected component versions, CVSS severity, indicators of compromise, and initial mitigation guidance.

3. **Stage 3 — Final Report (Within 14 Days):**
   * *Deadline:* Within 14 days after a corrective patch or mitigation is made available, or at most 1 month after the Stage 2 report.
   * *Content:* Comprehensive root cause analysis, permanent remediation details, and advice for downstream users.

---

## 3. Enforcement & Penalties

Under Article 64 of Regulation (EU) 2024/2847, failure to adhere to core reporting and security obligations carries administrative fines of:
* Up to **€15,000,000**, or
* Up to **2.5% of total worldwide annual turnover** for the preceding financial year, whichever is higher.

---

## 4. What `cra-watchtower` Covers

* ✅ **Automated Ingestion:** Parses machine-readable CycloneDX (v1.4, v1.5) and SPDX (v2.2, v2.3) SBOMs.
* ✅ **PURL Canonicalization:** Normalizes heterogeneous dependency formats into canonical Package URLs (`purl-spec`).
* ✅ **Exploited Matching:** Correlates components with OSV.dev and the CISA Known Exploited Vulnerabilities (KEV) catalog.
* ✅ **Awareness Clock Tracker:** Allows incident responders to record the exact awareness timestamp and calculates real-time countdowns for the 24h, 72h, and 14d deadlines.
* ✅ **Pre-Populated Draft Generator:** Generates standardized Markdown reports with verified technical facts pre-filled while explicitly highlighting fields requiring human legal/technical review.

---

## 5. Non-Goals & Limitations

* ❌ **No Automated Submission:** `cra-watchtower` never transmits data to ENISA's Single Reporting Platform or national CSIRTs.
* ❌ **Not Legal Advice:** Automated alerts are engineering aids. The legal trigger for CRA reporting is the organization's verified awareness, which requires human legal and security evaluation.
