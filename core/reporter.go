package core

import (
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
)

type Reporter struct {
	logger *utils.Logger
}

func NewReporter(logger *utils.Logger) *Reporter {
	return &Reporter{
		logger: logger,
	}
}

type ReportData struct {
	Title            string
	Date             string
	Target           string
	Vulnerabilities  []Vulnerability
	Summary          map[string]int
	ScanDuration     string
	ScanType         string
	TotalEndpoints   int
	TotalRequests    int
}

func (r *Reporter) GenerateReport(vulnerabilities []Vulnerability, filename, format string) error {
	r.logger.Info("Generating %s report with %d vulnerabilities", format, len(vulnerabilities))
	
	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}
	
	switch format {
	case "markdown":
		return r.generateMarkdownReport(vulnerabilities, filename)
	case "json":
		return r.generateJSONReport(vulnerabilities, filename)
	case "html":
		return r.generateHTMLReport(vulnerabilities, filename)
	case "pdf":
		return r.generatePDFReport(vulnerabilities, filename)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

func (r *Reporter) generateHTMLReport(vulnerabilities []Vulnerability, filename string) error {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .header {
            border-bottom: 2px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
            font-weight: bold;
        }
        .high { color: #dc3545; }
        .medium { color: #fd7e14; }
        .low { color: #28a745; }
        .vulnerability {
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }
        .vulnerability.high { border-color: #dc3545; background-color: #f8d7da; }
        .vulnerability.medium { border-color: #fd7e14; background-color: #fff3cd; }
        .vulnerability.low { border-color: #28a745; background-color: #d4edda; }
        .vuln-type { font-weight: bold; font-size: 1.2em; }
        .vuln-url { color: #007acc; word-break: break-all; }
        .vuln-description { margin: 10px 0; }
        .vuln-payload { 
            background-color: #e9ecef; 
            padding: 10px; 
            border-radius: 3px; 
            font-family: monospace; 
            overflow-x: auto; 
        }
        .vuln-remediation { 
            background-color: #d1ecf1; 
            padding: 10px; 
            border-radius: 3px; 
            margin-top: 10px; 
        }
        .vuln-references { font-size: 0.9em; color: #6c757d; }
        .chart-container {
            width: 400px;
            height: 400px;
            margin: 20px auto;
        }
        .risk-meter {
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            margin: 10px 0;
            overflow: hidden;
        }
        .risk-fill {
            height: 100%;
            border-radius: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #007acc;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{.Title}}</h1>
        <p><strong>Date:</strong> {{.Date}}</p>
        <p><strong>Target:</strong> {{.Target}}</p>
        <p><strong>Scan Type:</strong> {{.ScanType}}</p>
        <p><strong>Duration:</strong> {{.ScanDuration}}</p>
        <p><strong>Total Endpoints:</strong> {{.TotalEndpoints}}</p>
        <p><strong>Total Requests:</strong> {{.TotalRequests}}</p>
    </div>

    <div class="summary">
        <h2>Scan Summary</h2>
        <div class="summary-item high">High: {{.Summary.High}}</div>
        <div class="summary-item medium">Medium: {{.Summary.Medium}}</div>
        <div class="summary-item low">Low: {{.Summary.Low}}</div>
        <div class="summary-item">Total: {{len .Vulnerabilities}}</div>
        
        <div class="risk-meter">
            <div class="risk-fill" style="width: {{riskPercentage .Summary.High .Summary.Medium .Summary.Low}}%; 
                 background-color: {{riskColor .Summary.High .Summary.Medium .Summary.Low}};"></div>
        </div>
        <p>Overall Risk: {{overallRisk .Summary.High .Summary.Medium .Summary.Low}}</p>
    </div>

    <h2>Vulnerabilities</h2>
    {{range .Vulnerabilities}}
    <div class="vulnerability {{lower .Severity}}">
        <div class="vuln-type">{{.Type}} ({{.Severity}})</div>
        <div class="vuln-url"><strong>URL:</strong> {{.URL}}</div>
        <div class="vuln-description"><strong>Description:</strong> {{.Description}}</div>
        {{if .Payload}}<div class="vuln-payload"><strong>Payload:</strong> {{.Payload}}</div>{{end}}
        {{if .Evidence}}<div class="vuln-payload"><strong>Evidence:</strong> {{.Evidence}}</div>{{end}}
        {{if .Remediation}}<div class="vuln-remediation"><strong>Remediation:</strong> {{.Remediation}}</div>{{end}}
        {{if .CWE}}<div><strong>CWE:</strong> {{.CWE}}</div>{{end}}
        {{if .CVSS}}<div><strong>CVSS:</strong> {{.CVSS}}</div>{{end}}
        {{if .References}}<div class="vuln-references">
            <strong>References:</strong>
            <ul>
            {{range .References}}<li>{{.}}</li>{{end}}
            </ul>
        </div>{{end}}
    </div>
    {{else}}
    <div class="vulnerability low">
        <div class="vuln-type">No vulnerabilities found</div>
        <div class="vuln-description">The scan completed successfully and no vulnerabilities were detected.</div>
    </div>
    {{end}}

    <h2>Technical Details</h2>
    <table>
        <tr>
            <th>Type</th>
            <th>Count</th>
            <th>Percentage</th>
        </tr>
        {{range $type, $count := vulnerabilityTypes .Vulnerabilities}}
        <tr>
            <td>{{$type}}</td>
            <td>{{$count}}</td>
            <td>{{percentage $count (len $.Vulnerabilities)}}%</td>
        </tr>
        {{end}}
    </table>
</body>
</html>`

	funcMap := template.FuncMap{
		"lower": strings.ToLower,
		"riskPercentage": func(high, medium, low int) float64 {
			total := high + medium + low
			if total == 0 {
				return 0
			}
			return float64(high*100 + medium*50 + low*10) / float64(total)
		},
		"riskColor": func(high, medium, low int) string {
			total := high + medium + low
			if total == 0 {
				return "#28a745"
			}
			risk := float64(high*100 + medium*50 + low*10) / float64(total)
			if risk > 70 {
				return "#dc3545"
			} else if risk > 30 {
				return "#fd7e14"
			} else {
				return "#28a745"
			}
		},
		"overallRisk": func(high, medium, low int) string {
			total := high + medium + low
			if total == 0 {
				return "None"
			}
			risk := float64(high*100 + medium*50 + low*10) / float64(total)
			if risk > 70 {
				return "High"
			} else if risk > 30 {
				return "Medium"
			} else {
				return "Low"
			}
		},
		"vulnerabilityTypes": func(vulns []Vulnerability) map[string]int {
			types := make(map[string]int)
			for _, vuln := range vulns {
				types[vuln.Type]++
			}
			return types
		},
		"percentage": func(part, total int) float64 {
			if total == 0 {
				return 0
			}
			return float64(part) * 100 / float64(total)
		},
	}

	data := r.prepareReportData(vulnerabilities)
	t := template.Must(template.New("report").Funcs(funcMap).Parse(tmpl))
	
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	return t.Execute(file, data)
}

func (r *Reporter) generateJSONReport(vulnerabilities []Vulnerability, filename string) error {
	data := r.prepareReportData(vulnerabilities)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func (r *Reporter) generateMarkdownReport(vulnerabilities []Vulnerability, filename string) error {
	data := r.prepareReportData(vulnerabilities)
	
	content := fmt.Sprintf("# %s\n\n", data.Title)
	content += fmt.Sprintf("**Date:** %s\n\n", data.Date)
	content += fmt.Sprintf("**Target:** %s\n\n", data.Target)
	content += fmt.Sprintf("**Scan Type:** %s\n\n", data.ScanType)
	content += fmt.Sprintf("**Duration:** %s\n\n", data.ScanDuration)
	content += fmt.Sprintf("**Total Endpoints:** %d\n\n", data.TotalEndpoints)
	content += fmt.Sprintf("**Total Requests:** %d\n\n", data.TotalRequests)
	
	content += "## Summary\n\n"
	content += fmt.Sprintf("- **High:** %d\n", data.Summary["High"])
	content += fmt.Sprintf("- **Medium:** %d\n", data.Summary["Medium"])
	content += fmt.Sprintf("- **Low:** %d\n", data.Summary["Low"])
	content += fmt.Sprintf("- **Total:** %d\n\n", len(data.Vulnerabilities))
	
	content += "## Vulnerabilities\n\n"
	for _, vuln := range data.Vulnerabilities {
		content += fmt.Sprintf("### %s (%s)\n\n", vuln.Type, vuln.Severity)
		content += fmt.Sprintf("**URL:** %s\n\n", vuln.URL)
		content += fmt.Sprintf("**Description:** %s\n\n", vuln.Description)
		if vuln.Payload != "" {
			content += fmt.Sprintf("**Payload:** `%s`\n\n", vuln.Payload)
		}
		if vuln.Evidence != "" {
			content += fmt.Sprintf("**Evidence:** %s\n\n", vuln.Evidence)
		}
		if vuln.Remediation != "" {
			content += fmt.Sprintf("**Remediation:** %s\n\n", vuln.Remediation)
		}
		if vuln.CWE != "" {
			content += fmt.Sprintf("**CWE:** %s\n\n", vuln.CWE)
		}
		if vuln.CVSS > 0 {
			content += fmt.Sprintf("**CVSS:** %.1f\n\n", vuln.CVSS)
		}
		if len(vuln.References) > 0 {
			content += "**References:**\n\n"
			for _, ref := range vuln.References {
				content += fmt.Sprintf("- %s\n", ref)
			}
			content += "\n"
		}
		content += "---\n\n"
	}
	
	if len(data.Vulnerabilities) == 0 {
		content += "No vulnerabilities found.\n\n"
	}
	
	return os.WriteFile(filename, []byte(content), 0644)
}

func (r *Reporter) generatePDFReport(vulnerabilities []Vulnerability, filename string) error {
	// Generate HTML first
	htmlFile := strings.TrimSuffix(filename, ".pdf") + ".html"
	if err := r.generateHTMLReport(vulnerabilities, htmlFile); err != nil {
		return err
	}
	
	// Convert HTML to PDF using external tool
	// This requires wkhtmltopdf or similar to be installed
	cmd := exec.Command("wkhtmltopdf", htmlFile, filename)
	if err := cmd.Run(); err != nil {
		r.logger.Warn("PDF generation failed, falling back to HTML: %v", err)
		// Fall back to HTML if PDF generation fails
		return nil
	}
	
	// Remove temporary HTML file
	os.Remove(htmlFile)
	
	return nil
}

func (r *Reporter) prepareReportData(vulnerabilities []Vulnerability) ReportData {
	summary := map[string]int{"High": 0, "Medium": 0, "Low": 0, "Info": 0}
	for _, v := range vulnerabilities {
		summary[v.Severity]++
	}
	
	return ReportData{
		Title:           "ACVA Vulnerability Assessment Report",
		Date:           time.Now().Format("January 2, 2006 15:04:05 MST"),
		Target:         "Target URL", // Should be set from scanner
		Vulnerabilities: vulnerabilities,
		Summary:        summary,
		ScanDuration:   "1h 23m", // Should be calculated from actual scan time
		ScanType:       "Full Scan",
		TotalEndpoints: 150,      // Should be actual count
		TotalRequests:  1250,     // Should be actual count
	}
}
