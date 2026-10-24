// Package report provides standalone HTML dashboard and Markdown summary generation
// for EU Cyber Resilience Act (CRA) compliance audits.
package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"

	"github.com/hashim-work-svg/cra-watchtower/internal/clock"
	"github.com/hashim-work-svg/cra-watchtower/internal/matcher"
)

// ReportData aggregates all scan, match, and timeline data for reporting.
type ReportData struct {
	Result      matcher.MatchResult `json:"result"`
	Timeline    *clock.Timeline     `json:"timeline,omitempty"`
	GeneratedAt time.Time           `json:"generated_at"`
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CRA Compliance Dashboard - {{.Result.ProductName}}</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --heading: #f0f6fc;
      --accent: #58a6ff;
      --danger: #f85149;
      --warning: #d29922;
      --success: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header { margin-bottom: 2rem; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; }
    h1 { color: var(--heading); font-size: 1.8rem; margin-bottom: 0.5rem; }
    .meta { color: var(--text-muted); font-size: 0.9rem; }
    .disclaimer-banner {
      background: rgba(210, 153, 34, 0.15);
      border-left: 4px solid var(--warning);
      padding: 1rem;
      border-radius: 4px;
      margin-bottom: 2rem;
      font-size: 0.85rem;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1.2rem;
    }
    .stat-val { font-size: 2rem; font-weight: bold; color: var(--heading); }
    .stat-val.danger { color: var(--danger); }
    .stat-val.warning { color: var(--warning); }
    .stat-val.success { color: var(--success); }
    .stat-label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; }
    .section-title { color: var(--heading); margin: 2rem 0 1rem; font-size: 1.3rem; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
      margin-bottom: 2rem;
    }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #21262d; color: var(--heading); font-weight: 600; font-size: 0.85rem; }
    tr:hover { background: rgba(255,255,255,0.02); }
    .badge {
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
    }
    .badge-danger { background: rgba(248, 81, 73, 0.2); color: var(--danger); border: 1px solid var(--danger); }
    .badge-warning { background: rgba(210, 153, 34, 0.2); color: var(--warning); border: 1px solid var(--warning); }
    .badge-success { background: rgba(63, 185, 80, 0.2); color: var(--success); border: 1px solid var(--success); }
    .purl-code { font-family: monospace; font-size: 0.8rem; color: var(--accent); }
    footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>CRA Vulnerability Watchtower</h1>
      <div class="meta">
        Product: <strong>{{.Result.ProductName}}</strong> (v{{.Result.ProductVersion}}) | 
        Generated: {{.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}
      </div>
    </header>

    <div class="disclaimer-banner">
      <strong>DISCLAIMER: NOT LEGAL ADVICE</strong> — This dashboard is an automated technical compliance aid.
      Article 14 notifications under Regulation (EU) 2024/2847 must be reviewed and submitted by authorized legal and cybersecurity personnel.
    </div>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val">{{.Result.TotalComponents}}</div>
        <div class="stat-label">Ingested Components</div>
      </div>
      <div class="stat-card">
        <div class="stat-val {{if .Result.Findings}}warning{{else}}success{{end}}">{{len .Result.Findings}}</div>
        <div class="stat-label">Matched Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="stat-val {{if .Result.ExploitedCandidateCount}}danger{{else}}success{{end}}">{{.Result.ExploitedCandidateCount}}</div>
        <div class="stat-label">KEV Exploited Candidates</div>
      </div>
      {{if .Timeline}}
      <div class="stat-card">
        <div class="stat-val {{if eq .Timeline.EarlyWarning.Status "OVERDUE"}}danger{{else if eq .Timeline.EarlyWarning.Status "DUE SOON"}}warning{{else}}success{{end}}">
          {{.Timeline.EarlyWarning.Status}}
        </div>
        <div class="stat-label">Stage 1 (24h) Status</div>
      </div>
      {{end}}
    </div>

    {{if .Timeline}}
    <h2 class="section-title">Article 14 Statutory Reporting Clock</h2>
    <table>
      <thead>
        <tr>
          <th>STAGE</th>
          <th>DEADLINE (UTC)</th>
          <th>TIME REMAINING</th>
          <th>STATUS</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td><strong>Stage 1: Early Warning (24h)</strong></td>
          <td>{{.Timeline.EarlyWarning.Deadline.Format "2006-01-02 15:04:05 UTC"}}</td>
          <td>{{formatDuration .Timeline.EarlyWarning.Remaining}}</td>
          <td><span class="badge {{badgeClass .Timeline.EarlyWarning.Status}}">{{.Timeline.EarlyWarning.Status}}</span></td>
        </tr>
        <tr>
          <td><strong>Stage 2: Vulnerability Notification (72h)</strong></td>
          <td>{{.Timeline.Notification.Deadline.Format "2006-01-02 15:04:05 UTC"}}</td>
          <td>{{formatDuration .Timeline.Notification.Remaining}}</td>
          <td><span class="badge {{badgeClass .Timeline.Notification.Status}}">{{.Timeline.Notification.Status}}</span></td>
        </tr>
        {{if .Timeline.FinalReport}}
        <tr>
          <td><strong>Stage 3: Final Report (14d after mitigation)</strong></td>
          <td>{{.Timeline.FinalReport.Deadline.Format "2006-01-02 15:04:05 UTC"}}</td>
          <td>{{formatDuration .Timeline.FinalReport.Remaining}}</td>
          <td><span class="badge {{badgeClass .Timeline.FinalReport.Status}}">{{.Timeline.FinalReport.Status}}</span></td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{end}}

    <h2 class="section-title">Vulnerability Findings</h2>
    {{if .Result.Findings}}
    <table>
      <thead>
        <tr>
          <th>CVE / VULN ID</th>
          <th>COMPONENT</th>
          <th>VERSION</th>
          <th>SEVERITY</th>
          <th>EXPLOITED (KEV)</th>
          <th>FIXED IN</th>
        </tr>
      </thead>
      <tbody>
        {{range .Result.Findings}}
        <tr>
          <td><strong>{{.CVEID}}</strong></td>
          <td>{{.Component.Name}}<br><span class="purl-code">{{.Component.PURL}}</span></td>
          <td>{{.Component.Version}}</td>
          <td>{{.Severity}}</td>
          <td>
            {{if .IsActivelyExploitedCandidate}}
              <span class="badge badge-danger">KEV EXPLOITED</span>
            {{else}}
              <span class="badge badge-success">NO</span>
            {{end}}
          </td>
          <td>{{if .FixedIn}}<code>{{.FixedIn}}</code>{{else}}<em>None</em>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
    {{else}}
    <p style="color: var(--success); padding: 1rem; background: var(--card-bg); border-radius: 6px;">No known vulnerabilities identified in ingested dependencies.</p>
    {{end}}

    <footer>
      CRA Vulnerability Watchtower &bull; EU Cyber Resilience Act Compliance Engine
    </footer>
  </div>
</body>
</html>`

// GenerateHTML renders an interactive standalone HTML compliance dashboard.
func GenerateHTML(data ReportData) (string, error) {
	funcMap := template.FuncMap{
		"formatDuration": clock.FormatDuration,
		"badgeClass": func(status clock.ClockStatus) string {
			switch status {
			case clock.StatusOverdue:
				return "badge-danger"
			case clock.StatusDueSoon:
				return "badge-warning"
			default:
				return "badge-success"
			}
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse html template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute html report template: %w", err)
	}

	return buf.String(), nil
}

// GenerateMarkdown renders an executive summary of the compliance scan in Markdown.
func GenerateMarkdown(data ReportData) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# CRA Compliance Scan Summary: %s (v%s)\n\n", data.Result.ProductName, data.Result.ProductVersion))
	sb.WriteString("> **DISCLAIMER:** NOT LEGAL ADVICE. Technical compliance aid under EU CRA Regulation (EU) 2024/2847.\n\n")

	sb.WriteString(fmt.Sprintf("- **Generated At:** %s\n", data.GeneratedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("- **Total Components:** %d\n", data.Result.TotalComponents))
	sb.WriteString(fmt.Sprintf("- **Vulnerabilities Identified:** %d\n", len(data.Result.Findings)))
	sb.WriteString(fmt.Sprintf("- **KEV Actively Exploited Candidates:** %d\n\n", data.Result.ExploitedCandidateCount))

	if data.Timeline != nil {
		sb.WriteString("## Article 14 Reporting Timeline\n\n")
		sb.WriteString("| Stage | Deadline (UTC) | Status |\n")
		sb.WriteString("|---|---|---|\n")
		sb.WriteString(fmt.Sprintf("| Stage 1: Early Warning (24h) | %s | %s |\n",
			data.Timeline.EarlyWarning.Deadline.Format(time.RFC3339), data.Timeline.EarlyWarning.Status))
		sb.WriteString(fmt.Sprintf("| Stage 2: Notification (72h) | %s | %s |\n",
			data.Timeline.Notification.Deadline.Format(time.RFC3339), data.Timeline.Notification.Status))
		if data.Timeline.FinalReport != nil {
			sb.WriteString(fmt.Sprintf("| Stage 3: Final Report (14d) | %s | %s |\n",
				data.Timeline.FinalReport.Deadline.Format(time.RFC3339), data.Timeline.FinalReport.Status))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## Findings\n\n")
	if len(data.Result.Findings) == 0 {
		sb.WriteString("No vulnerabilities identified.\n")
	} else {
		sb.WriteString("| CVE / ID | Component | Version | Severity | KEV Exploited | Fixed In |\n")
		sb.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range data.Result.Findings {
			exploitedStr := "No"
			if f.IsActivelyExploitedCandidate {
				exploitedStr = "**YES (KEV)**"
			}
			fixedStr := f.FixedIn
			if fixedStr == "" {
				fixedStr = "None"
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				f.CVEID, f.Component.Name, f.Component.Version, f.Severity, exploitedStr, fixedStr))
		}
	}

	return sb.String()
}

// WriteHTMLReport saves the rendered HTML dashboard to the specified destination path.
func WriteHTMLReport(data ReportData, filePath string) error {
	html, err := GenerateHTML(data)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte(html), 0644)
}
