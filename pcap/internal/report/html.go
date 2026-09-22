package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"strings"

	"github.com/agentpcap/agentpcap/internal/analyzer"
	"github.com/agentpcap/agentpcap/internal/pathology"
	"github.com/agentpcap/agentpcap/pkg/apcap"
)

// GenerateHTMLReport exports an APCAP capture as a standalone, zero-dependency offline HTML report.
func GenerateHTMLReport(cap *apcap.Capture, outputPath string) error {
	pEng := pathology.NewEngine()
	findings := pEng.Analyze(cap.Events)
	criticalPath := analyzer.AnalyzeCriticalPath(cap.Events)

	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AgentPCAP Report - ` + html.EscapeString(cap.Manifest.CaptureID) + `</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card: #111827;
      --border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --a2a: #38bdf8;
      --mcp: #c084fc;
      --model: #34d399;
      --tool: #fbbf24;
      --error: #f87171;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 32px;
      line-height: 1.5;
    }
    .container { max-width: 960px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 20px; margin-bottom: 24px; }
    .brand { font-size: 22px; font-weight: 800; }
    .brand span { color: var(--a2a); }
    .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
    .stat-label { font-size: 11px; color: var(--text-muted); font-family: monospace; }
    .stat-val { font-size: 22px; font-weight: 700; margin-top: 4px; }
    .section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 24px; }
    .section h3 { margin-top: 0; font-size: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; font-family: monospace; font-size: 12px; margin-top: 12px; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--text-muted); }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; }
    .badge-high { background: rgba(248, 113, 113, 0.2); color: var(--error); }
    .badge-med { background: rgba(251, 191, 36, 0.2); color: var(--tool); }
    .badge-low { background: rgba(56, 189, 248, 0.2); color: var(--a2a); }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">Agent<span>PCAP</span> Forensic Report</div>
      <div style="font-family: monospace; font-size: 12px; color: var(--text-muted);">
        Capture ID: ` + html.EscapeString(cap.Manifest.CaptureID) + `
      </div>
    </div>

    <!-- Summary Metrics -->
    <div class="grid">
      <div class="card">
        <div class="stat-label">TOTAL DURATION</div>
        <div class="stat-val">` + fmt.Sprintf("%.2fs", cap.Metadata.TotalDurationMs/1000.0) + `</div>
      </div>
      <div class="card">
        <div class="stat-label">TOTAL TOKENS</div>
        <div class="stat-val" style="color: var(--a2a);">` + fmt.Sprintf("%d", cap.Metadata.TotalTokens.TotalTokens) + `</div>
      </div>
      <div class="card">
        <div class="stat-label">ESTIMATED COST</div>
        <div class="stat-val" style="color: var(--model);">` + fmt.Sprintf("$%.4f", cap.Metadata.TotalCost) + `</div>
      </div>
      <div class="card">
        <div class="stat-label">TOTAL EVENTS / ERRORS</div>
        <div class="stat-val" style="color: ` + map[bool]string{true: "var(--error)", false: "var(--text)"}[cap.Metadata.ErrorCount > 0] + `;">` + fmt.Sprintf("%d / %d", len(cap.Events), cap.Metadata.ErrorCount) + `</div>
      </div>
    </div>

    <!-- Critical Path Section -->
    <div class="section">
      <h3>⚡ Critical Path & Execution Bottlenecks</h3>
      <p>` + html.EscapeString(criticalPath.Summary) + `</p>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>OPERATION</th>
            <th>PROTOCOL</th>
            <th>DURATION</th>
            <th>% WALL-CLOCK</th>
          </tr>
        </thead>
        <tbody>`)

	for i, step := range criticalPath.Steps {
		sb.WriteString(fmt.Sprintf(`
          <tr>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
            <td>%.1fms</td>
            <td>%.1f%%</td>
          </tr>`, i+1, html.EscapeString(step.Operation), html.EscapeString(step.Protocol), step.DurationMs, step.PercentOfTotal))
	}

	sb.WriteString(`
        </tbody>
      </table>
    </div>

    <!-- Findings Section -->
    <div class="section">
      <h3>⚠ Pathology & Anomaly Findings (` + fmt.Sprintf("%d", len(findings)) + `)</h3>`)

	if len(findings) == 0 {
		sb.WriteString(`<p style="color: var(--model); font-family: monospace;">✓ No runtime pathologies detected.</p>`)
	} else {
		for _, f := range findings {
			badgeClass := "badge-low"
			if f.Severity == "HIGH" {
				badgeClass = "badge-high"
			} else if f.Severity == "MEDIUM" {
				badgeClass = "badge-med"
			}

			sb.WriteString(fmt.Sprintf(`
        <div style="border-left: 3px solid var(--border); padding-left: 12px; margin-bottom: 16px;">
          <div style="display: flex; gap: 8px; align-items: center;">
            <span class="badge %s">%s</span>
            <strong>%s</strong>
          </div>
          <p style="margin: 6px 0; font-size: 13px;">%s</p>
          <div style="font-size: 12px; color: var(--a2a); font-family: monospace;">Suggested Fix: %s</div>
        </div>`, badgeClass, f.Severity, html.EscapeString(f.Title), html.EscapeString(f.Explanation), html.EscapeString(f.SuggestedFix)))
		}
	}

	sb.WriteString(`
    </div>

    <!-- Top 20 Packets Sample -->
    <div class="section">
      <h3>📋 Packet Activity Log</h3>
      <table>
        <thead>
          <tr>
            <th>TIME (ms)</th>
            <th>PROTO</th>
            <th>SOURCE</th>
            <th>DESTINATION</th>
            <th>OPERATION</th>
            <th>DURATION</th>
            <th>STATUS</th>
          </tr>
        </thead>
        <tbody>`)

	limit := 25
	if len(cap.Events) < limit {
		limit = len(cap.Events)
	}

	for i := 0; i < limit; i++ {
		ev := cap.Events[i]
		sb.WriteString(fmt.Sprintf(`
          <tr>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%s</td>
            <td>%.1fms</td>
            <td style="color: %s;">%s</td>
          </tr>`, i+1, html.EscapeString(string(ev.Protocol)), html.EscapeString(ev.Source.Name), html.EscapeString(ev.Destination.Name), html.EscapeString(ev.Operation), ev.DurationMs, map[bool]string{true: "var(--error)", false: "var(--model)"}[ev.Status == "ERROR"], string(ev.Status)))
	}

	sb.WriteString(`
        </tbody>
      </table>
    </div>

    <div style="text-align: center; font-size: 11px; color: var(--text-muted); font-family: monospace; margin-top: 32px;">
      Generated by AgentPCAP v1.0.0 — Open Protocol Capture Engine for AI Agents
    </div>
  </div>
</body>
</html>`)

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

// Dummy helper
var _ = json.Marshal
