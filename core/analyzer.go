package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/sabbir-lite-0/acva/utils"
	"github.com/sabbir-lite-0/acva/core/gemini"
)

type Analyzer struct {
	logger       *utils.Logger
	config       utils.Config
	client       *utils.HTTPClient
	geminiClient *gemini.GeminiClient
}

func NewAnalyzer(logger *utils.Logger, config utils.Config, client *utils.HTTPClient, geminiClient *gemini.GeminiClient) *Analyzer {
	return &Analyzer{
		logger:       logger,
		config:       config,
		client:       client,
		geminiClient: geminiClient,
	}
}

func (a *Analyzer) Analyze(endpoints []string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	a.logger.Info("Analyzing %d endpoints for vulnerabilities", len(endpoints))
	
	// Create a worker pool for concurrent analysis
	pool := utils.NewWorkerPool(a.config.Scan.ConcurrentRequests, a.config.Scan.Retries, 
		time.Duration(a.config.Scan.Delay)*time.Millisecond)
	
	results := make(chan []Vulnerability, len(endpoints))
	
	for _, endpoint := range endpoints {
		endpoint := endpoint // Create a local copy for the goroutine
		pool.Submit(func() error {
			endpointVulns := a.analyzeEndpoint(endpoint)
			if len(endpointVulns) > 0 {
				results <- endpointVulns
			}
			return nil
		})
	}
	
	// Wait for all workers to complete
	pool.Wait()
	close(results)
	
	// Collect results
	for vulns := range results {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	return vulnerabilities, nil
}

func (a *Analyzer) analyzeEndpoint(endpoint string) []Vulnerability {
	var vulnerabilities []Vulnerability
	a.logger.Debug("Analyzing endpoint: %s", endpoint)
	
	// Get response for advanced analysis
	response, err := a.client.Get(endpoint)
	if err != nil {
		return vulnerabilities
	}
	
	// Advanced AI analysis if Gemini is enabled
	if a.geminiClient != nil {
		advancedVulns, err := a.AdvancedAnalysis(endpoint, response)
		if err != nil {
			a.logger.Debug("Advanced analysis failed: %v", err)
		} else {
			vulnerabilities = append(vulnerabilities, advancedVulns...)
		}
	}
	
	// Check for path traversal
	if a.config.Vulnerabilities.PathTraversal {
		if vulns := a.checkPathTraversal(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Check for sensitive files
	if a.config.Vulnerabilities.SensitiveFiles {
		if vulns := a.checkSensitiveFiles(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Check for admin endpoints
	if vulns := a.checkAdminEndpoints(endpoint); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	// Check for open redirects
	if a.config.Vulnerabilities.OpenRedirect {
		if vulns := a.checkOpenRedirect(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Check for JWT issues
	if a.config.Vulnerabilities.JWTSecurity {
		if vulns := a.checkJWT(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Check for XXE
	if a.config.Vulnerabilities.XXE {
		if vulns := a.checkXXE(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Check for IDOR patterns
	if a.config.Vulnerabilities.InsecureDirectObjectReference {
		if vulns := a.checkIDOR(endpoint); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	return vulnerabilities
}

// Add advanced analysis methods
func (a *Analyzer) AdvancedAnalysis(endpoint, responseBody string) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	
	// Advanced SQL Injection detection with AI confirmation
	if a.config.Vulnerabilities.SQLInjection {
		if a.isPotentialSQLi(responseBody) {
			if a.geminiClient != nil {
				confirmed, reason, err := a.geminiClient.AnalyzeResponse(responseBody, "", "SQL Injection")
				if err == nil && confirmed {
					vuln := Vulnerability{
						Type:        "SQL Injection",
						URL:         endpoint,
						Severity:    "High",
						Description: "AI-confirmed SQL Injection vulnerability: " + reason,
						CWE:         "CWE-89",
						CVSS:        8.8,
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}
	
	// Similar advanced checks for other vulnerability types
	// XSS detection
	if a.config.Vulnerabilities.XSS {
		if a.isPotentialXSS(responseBody) {
			if a.geminiClient != nil {
				confirmed, reason, err := a.geminiClient.AnalyzeResponse(responseBody, "", "XSS")
				if err == nil && confirmed {
					vuln := Vulnerability{
						Type:        "XSS",
						URL:         endpoint,
						Severity:    "High",
						Description: "AI-confirmed XSS vulnerability: " + reason,
						CWE:         "CWE-79",
						CVSS:        8.1,
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}
	
	// Command Injection detection
	if a.config.Vulnerabilities.CommandInjection {
		if a.isPotentialCommandInjection(responseBody) {
			if a.geminiClient != nil {
				confirmed, reason, err := a.geminiClient.AnalyzeResponse(responseBody, "", "Command Injection")
				if err == nil && confirmed {
					vuln := Vulnerability{
						Type:        "Command Injection",
						URL:         endpoint,
						Severity:    "High",
						Description: "AI-confirmed Command Injection vulnerability: " + reason,
						CWE:         "CWE-78",
						CVSS:        9.1,
					}
					vulnerabilities = append(vulnerabilities, vuln)
				}
			}
		}
	}
	
	return vulnerabilities, nil
}

// Add more sophisticated detection methods
func (a *Analyzer) isPotentialSQLi(response string) bool {
	// Advanced SQL error patterns
	patterns := []string{
		`(?i)(sql syntax.*error|syntax error.*sql)`,
		`(?i)(mysql.*error|warning.*mysql)`,
		`(?i)(ORA-[0-9]{5})`,
		`(?i)(PostgreSQL.*ERROR)`,
		`(?i)(Driver.*SQL[-\_ ]*Server)`,
		`(?i)(Unclosed quotation mark)`,
		`(?i)(quoted string not properly terminated)`,
	}
	
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, response); matched {
			return true
		}
	}
	return false
}

func (a *Analyzer) isPotentialXSS(response string) bool {
	// XSS patterns
	patterns := []string{
		`(?i)<script>`,
		`(?i)javascript:`,
		`(?i)onerror=`,
		`(?i)onload=`,
		`(?i)onclick=`,
		`(?i)alert\(`,
		`(?i)document\.cookie`,
	}
	
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, response); matched {
			return true
		}
	}
	return false
}

func (a *Analyzer) isPotentialCommandInjection(response string) bool {
	// Command injection patterns
	patterns := []string{
		`(?i)(bin/bash|bin/sh)`,
		`(?i)(cmd\.exe|command\.com)`,
		`(?i)(whoami|id|ls|dir)`,
		`(?i)(root|administrator)`,
		`(?i)(nt authority|linux|windows)`,
	}
	
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, response); matched {
			return true
		}
	}
	return false
}

func (a *Analyzer) checkPathTraversal(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	patterns := []string{
		`\.\./`, `\.\.\\`, `\.\.%2f`, `\.\.%5c`,
		`%2e%2e/`, `%2e%2e\\`, `\.\.0x2f`, `\.\.0x5c`,
	}
	
	// Also check URL-encoded versions
	for _, pattern := range patterns {
		regex := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(pattern))
		if regex.MatchString(urlStr) {
			vuln := Vulnerability{
				Type:        "Path Traversal",
				URL:         urlStr,
				Severity:    "High",
				Description: "Potential path traversal vulnerability detected in URL",
				Payload:     pattern,
				CWE:         "CWE-22",
				CVSS:        8.6,
				Remediation: "Validate and sanitize all user input used in file paths",
				References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities
}

func (a *Analyzer) checkSensitiveFiles(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	sensitiveFiles := []string{
		".env", ".git/", ".svn/", ".DS_Store", 
		"web.config", "php.ini", "config.php", "config.json",
		"robots.txt", "sitemap.xml", "backup", "dump", 
		"sql", "password", "credential", "secret",
		"wp-config.php", "configuration.yml", "settings.py",
		"appsettings.json", "dockerfile", "docker-compose.yml",
		"jenkins", "jenkins/", "grafana/", "kibana/",
	}
	
	urlLower := strings.ToLower(urlStr)
	for _, file := range sensitiveFiles {
		if strings.Contains(urlLower, file) {
			vuln := Vulnerability{
				Type:        "Sensitive File Exposure",
				URL:         urlStr,
				Severity:    "Medium",
				Description: "Potential sensitive file or directory exposure detected",
				Payload:     file,
				CWE:         "CWE-538",
				CVSS:        5.3,
				Remediation: "Restrict access to sensitive files and directories",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities
}

func (a *Analyzer) checkAdminEndpoints(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	adminPatterns := []string{
		"admin", "administrator", "wp-admin", "dashboard",
		"login", "signin", "auth", "authenticate",
		"console", "manager", "management", "control",
		"cpanel", "whm", "webmail", "phpmyadmin",
		"adminer", "rockmongo", "mongoadmin",
	}
	
	urlLower := strings.ToLower(urlStr)
	for _, pattern := range adminPatterns {
		if strings.Contains(urlLower, pattern) {
			vuln := Vulnerability{
				Type:        "Admin Endpoint Exposure",
				URL:         urlStr,
				Severity:    "Low",
				Description: "Admin or authentication endpoint detected",
				Payload:     pattern,
				CWE:         "CWE-200",
				CVSS:        3.5,
				Remediation: "Implement proper access controls and consider obfuscating admin URLs",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities
}

func (a *Analyzer) checkOpenRedirect(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	query := parsed.Query()
	for param, values := range query {
		paramLower := strings.ToLower(param)
		redirectParams := []string{"redirect", "redirect_uri", "return", "returnurl", "url", "next", "continue"}
		
		for _, redirectParam := range redirectParams {
			if strings.Contains(paramLower, redirectParam) {
				for _, value := range values {
					if isExternalURL(value, parsed.Hostname()) && !isAllowedRedirect(value, parsed.Hostname()) {
						vuln := Vulnerability{
							Type:        "Open Redirect",
							URL:         urlStr,
							Severity:    "Medium",
							Description: "Potential open redirect vulnerability detected",
							Payload:     param + "=" + value,
							CWE:         "CWE-601",
							CVSS:        6.1,
							Remediation: "Validate redirect URLs against an allowlist",
							References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/04-Testing_for_Client_Side_URL_Redirect"},
						}
						vulnerabilities = append(vulnerabilities, vuln)
					}
				}
			}
		}
	}
	
	return vulnerabilities
}

func isExternalURL(urlStr, currentHost string) bool {
	if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
		parsed, err := url.Parse(urlStr)
		if err != nil {
			return false
		}
		return parsed.Hostname() != currentHost
	}
	return false
}

func isAllowedRedirect(urlStr, currentHost string) bool {
	// Implement allowlist logic here
	allowedDomains := []string{currentHost, "example.com", "trusted-domain.com"}
	
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	for _, domain := range allowedDomains {
		if parsed.Hostname() == domain {
			return true
		}
	}
	
	return false
}

func (a *Analyzer) checkJWT(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check for JWT tokens in URL parameters
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	query := parsed.Query()
	for _, values := range query {
		for _, value := range values {
			if isJWT(value) {
				vuln := Vulnerability{
					Type:        "JWT in URL",
					URL:         urlStr,
					Severity:    "Medium",
					Description: "JWT token detected in URL parameter",
					Payload:     value,
					CWE:         "CWE-598",
					CVSS:        5.3,
					Remediation: "Avoid passing JWT tokens in URL parameters",
					References:  []string{"https://auth0.com/docs/security/tokens/json-web-tokens"},
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities
}

func isJWT(token string) bool {
	// JWT pattern: three base64url-encoded parts separated by dots
	jwtPattern := `^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$`
	matched, _ := regexp.MatchString(jwtPattern, token)
	return matched && len(token) > 30
}

func (a *Analyzer) checkXXE(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check for XML parameters in URL
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	query := parsed.Query()
	for param, values := range query {
		paramLower := strings.ToLower(param)
		xmlParams := []string{"xml", "soap", "rss", "atom", "feed"}
		
		for _, xmlParam := range xmlParams {
			if strings.Contains(paramLower, xmlParam) {
				for _, value := range values {
					if strings.Contains(strings.ToLower(value), "<!doctype") || 
					   strings.Contains(strings.ToLower(value), "<?xml") {
						vuln := Vulnerability{
							Type:        "Potential XXE",
							URL:         urlStr,
							Severity:    "High",
							Description: "XML content detected in parameter, potential XXE vulnerability",
							Payload:     param + "=" + value,
							CWE:         "CWE-611",
							CVSS:        8.2,
							Remediation: "Disable XML external entity processing",
							References:  []string{"https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"},
						}
						vulnerabilities = append(vulnerabilities, vuln)
					}
				}
			}
		}
	}
	
	return vulnerabilities
}

func (a *Analyzer) checkIDOR(urlStr string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check for IDOR patterns in URL
	idorPatterns := []*regexp.Regexp{
		regexp.MustCompile(`/(users?|profiles?|accounts?)/(\d+)`),
		regexp.MustCompile(`/api/(v\d+/)?(users?|profiles?|accounts?)/(\d+)`),
		regexp.MustCompile(`id=(\d+)`),
		regexp.MustCompile(`user[_-]?id=(\d+)`),
		regexp.MustCompile(`account[_-]?id=(\d+)`),
	}
	
	for _, pattern := range idorPatterns {
		if pattern.MatchString(urlStr) {
			matches := pattern.FindStringSubmatch(urlStr)
			if len(matches) > 1 {
				vuln := Vulnerability{
					Type:        "Potential IDOR",
					URL:         urlStr,
					Severity:    "Medium",
					Description: "Potential Insecure Direct Object Reference detected",
					Payload:     matches[0],
					CWE:         "CWE-639",
					CVSS:        6.5,
					Remediation: "Implement proper authorization checks for all object references",
					References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References"},
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities
}

// Helper function to generate a unique hash for a vulnerability
func (v *Vulnerability) Hash() string {
	hashInput := v.Type + v.URL + v.Payload
	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}
