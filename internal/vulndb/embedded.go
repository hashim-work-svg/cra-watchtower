package vulndb

// EmbeddedOSVFixtures contains pre-packaged OSV vulnerability records for offline operation and demos.
const EmbeddedOSVFixtures = `[
  {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "summary": "Remote code execution in Log4j 2",
    "details": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
    "aliases": ["CVE-2021-44228"],
    "published": "2021-12-10T10:00:00Z",
    "modified": "2023-01-15T12:00:00Z",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
      }
    ],
    "affected": [
      {
        "package": {
          "ecosystem": "Maven",
          "name": "org.apache.logging.log4j:log4j-core",
          "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"
        },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {
                "introduced": "2.0-beta9"
              },
              {
                "fixed": "2.15.0"
              }
            ]
          }
        ],
        "versions": ["2.14.0", "2.14.1"]
      }
    ],
    "references": [
      {
        "type": "ADVISORY",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      }
    ]
  },
  {
    "id": "GHSA-599f-7c49-w659",
    "summary": "Apache Commons Text arbitrary code execution",
    "details": "Apache Commons Text 1.5 through 1.9 performs variable interpolation, allowing arbitrary code execution when untrusted input is interpolated via script, dns, or url lookups.",
    "aliases": ["CVE-2022-42889"],
    "published": "2022-10-13T12:00:00Z",
    "modified": "2023-02-01T12:00:00Z",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      }
    ],
    "affected": [
      {
        "package": {
          "ecosystem": "Maven",
          "name": "org.apache.commons:commons-text",
          "purl": "pkg:maven/org.apache.commons/commons-text"
        },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {
                "introduced": "1.5"
              },
              {
                "fixed": "1.10.0"
              }
            ]
          }
        ],
        "versions": ["1.8", "1.9"]
      }
    ],
    "references": [
      {
        "type": "ADVISORY",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-42889"
      }
    ]
  },
  {
    "id": "CURL-CVE-2021-22901",
    "summary": "curl TLS certificate check bypass with OpenSSL",
    "details": "curl can be tricked into not verifying the server certificate when using OpenSSL under specific cipher configuration options.",
    "aliases": ["CVE-2021-22901"],
    "published": "2021-05-26T00:00:00Z",
    "modified": "2022-04-10T00:00:00Z",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
      }
    ],
    "affected": [
      {
        "package": {
          "ecosystem": "generic",
          "name": "curl",
          "purl": "pkg:generic/curl"
        },
        "ranges": [
          {
            "type": "ECOSYSTEM",
            "events": [
              {
                "introduced": "7.75.0"
              },
              {
                "fixed": "7.77.0"
              }
            ]
          }
        ],
        "versions": ["7.84.0"]
      }
    ],
    "references": [
      {
        "type": "ADVISORY",
        "url": "https://curl.se/docs/CVE-2021-22901.html"
      }
    ]
  },
  {
    "id": "GO-2022-0965",
    "summary": "Denial of service in net/http HTTP/2 server",
    "details": "An unauthenticated attacker can cause excessive memory consumption by sending large HTTP/2 requests with unbounded headers.",
    "aliases": ["CVE-2022-27664"],
    "published": "2022-09-08T00:00:00Z",
    "modified": "2023-01-01T00:00:00Z",
    "severity": [
      {
        "type": "CVSS_V3",
        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
      }
    ],
    "affected": [
      {
        "package": {
          "ecosystem": "Go",
          "name": "golang.org/x/crypto",
          "purl": "pkg:golang/golang.org/x/crypto"
        },
        "ranges": [
          {
            "type": "SEMVER",
            "events": [
              {
                "introduced": "0"
              },
              {
                "fixed": "v0.2.0"
              }
            ]
          }
        ],
        "versions": ["v0.1.0"]
      }
    ],
    "references": [
      {
        "type": "ADVISORY",
        "url": "https://pkg.go.dev/vuln/GO-2022-0965"
      }
    ]
  }
]`

// EmbeddedKEVFixtures contains pre-packaged CISA KEV catalog records.
const EmbeddedKEVFixtures = `{
  "title": "CISA Known Exploited Vulnerabilities Catalog (Embedded Excerpt)",
  "catalogVersion": "2026.10.24",
  "dateReleased": "2026-10-24T00:00:00Z",
  "count": 3,
  "vulnerabilities": [
    {
      "cveID": "CVE-2021-44228",
      "vendorProject": "Apache",
      "product": "Log4j",
      "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
      "dateAdded": "2021-12-10",
      "shortDescription": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints, allowing unauthenticated remote code execution.",
      "requiredAction": "Apply updates per vendor instructions or mitigate per CISA Emergency Directive 22-02.",
      "dueDate": "2021-12-24",
      "knownRansomwareCampaignUse": "Known",
      "notes": "Commonly referred to as Log4Shell. Extensive active exploitation observed globally."
    },
    {
      "cveID": "CVE-2022-42889",
      "vendorProject": "Apache",
      "product": "Commons Text",
      "vulnerabilityName": "Apache Commons Text Remote Code Execution Vulnerability",
      "dateAdded": "2022-10-25",
      "shortDescription": "Apache Commons Text contains an arbitrary code execution vulnerability due to variable interpolation flaws.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2022-11-15",
      "knownRansomwareCampaignUse": "Known",
      "notes": "Referred to as Text4Shell."
    },
    {
      "cveID": "CVE-2023-44487",
      "vendorProject": "Multiple",
      "product": "HTTP/2 Protocol Implementations",
      "vulnerabilityName": "HTTP/2 Rapid Reset Denial-of-Service Vulnerability",
      "dateAdded": "2023-10-10",
      "shortDescription": "The HTTP/2 protocol is susceptible to denial of service attacks via rapid stream resets (RST_STREAM).",
      "requiredAction": "Apply mitigations or updates per vendor guidance.",
      "dueDate": "2023-10-31",
      "knownRansomwareCampaignUse": "Known",
      "notes": "Coordinated disclosure across multiple web server and proxy vendors."
    }
  ]
}`
