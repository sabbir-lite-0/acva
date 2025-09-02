package core

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/sabbir-lite-0/acva/utils"
)

// EnhancedFuzzer extends the base fuzzer with advanced payloads and techniques
type EnhancedFuzzer struct {
	*Fuzzer
	advancedWordlist []string
}

func NewEnhancedFuzzer(logger *utils.Logger, config utils.Config, client *utils.HTTPClient) *EnhancedFuzzer {
	baseFuzzer := NewFuzzer(logger, config, client)
	enhanced := &EnhancedFuzzer{
		Fuzzer: baseFuzzer,
	}
	
	// Load advanced wordlists
	enhanced.loadAdvancedWordlists()
	
	return enhanced
}

func (f *EnhancedFuzzer) Fuzz(endpoints []string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	f.logger.Info("Starting advanced fuzzing with %d payloads across %d endpoints", 
		len(f.wordlist)+len(f.advancedWordlist), len(endpoints))
	
	// Combine standard and advanced wordlists
	allPayloads := append(f.wordlist, f.advancedWordlist...)
	
	// Create a worker pool for concurrent fuzzing
	pool := utils.NewWorkerPool(f.config.Scan.ConcurrentRequests, f.config.Scan.Retries, 
		time.Duration(f.config.Scan.Delay)*time.Millisecond)
	
	results := make(chan []Vulnerability, len(endpoints)*len(allPayloads))
	
	totalTests := len(endpoints) * len(allPayloads)
	if progress != nil {
		progress.AddTask("Fuzzing endpoints", totalTests)
	}
	
	for _, endpoint := range endpoints {
		for _, payload := range allPayloads {
			endpoint, payload := endpoint, payload
			
			pool.Submit(func() error {
				fuzzedURLs := f.generateFuzzedURLs(endpoint, payload)
				for _, fuzzedURL := range fuzzedURLs {
					vulns := f.testPayloadAdvanced(fuzzedURL, payload)
					if len(vulns) > 0 {
						results <- vulns
					}
				}
				
				if progress != nil {
					progress.IncrementTask("Fuzzing endpoints", 1)
				}
				
				return nil
			})
		}
	}
	
	// Wait for all workers to complete
	pool.Wait()
	close(results)
	
	// Collect results
	for vulns := range results {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if progress != nil {
		progress.CompleteTask("Fuzzing endpoints")
	}
	
	return vulnerabilities, nil
}

func (f *EnhancedFuzzer) loadAdvancedWordlists() {
	var advancedWords []string
	
	// Load advanced payloads for modern vulnerabilities
	advancedPayloads := []string{
		// Prototype pollution payloads
		"__proto__[test]=test",
		"constructor[prototype][test]=test",
		"constructor.prototype.test=test",
		
		// GraphQL injection payloads
		"{__schema{types{name,fields{name}}}}",
		"query{__typename}",
		"query{user(id:\"1\"){id,name,email}}",
		
		// JWT manipulation payloads
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.-",
		"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.e30.",
		
		// Advanced SSRF bypass payloads
		"http://localhost:80@example.com",
		"http://127.0.0.1:80/",
		"http://[::1]:80/",
		"http://2130706433/",
		"http://0x7f000001/",
		"http://0177.0000.0000.0001/",
		
		// Cloud metadata endpoints
		"http://169.254.169.254/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/metadata/instance?api-version=2020-06-01",
		
		// WebSocket injection payloads
		"ws://evil.com",
		"wss://evil.com",
		
		// Business logic bypass payloads
		"../admin",
		"....//admin",
		"..;/admin",
		"%2e%2e%2fadmin",
		
		// Template injection payloads
		"${7*7}",
		"#{7*7}",
		"{{7*7}}",
		"<%= 7*7 %>",
	}
	
	// Load from external wordlist files if available
	wordlistFiles := []string{
		"wordlists/advanced_payloads.txt",
		"wordlists/graphql.txt",
		"wordlists/ssrf.txt",
		"wordlists/jwt.txt",
		"wordlists/prototype_pollution.txt",
	}
	
	for _, file := range wordlistFiles {
		if words, err := f.loadWordlist(file); err == nil {
			advancedWords = append(advancedWords, words...)
		}
	}
	
	// Combine built-in and loaded payloads
	f.advancedWordlist = append(advancedPayloads, advancedWords...)
	f.logger.Info("Loaded %d advanced payloads", len(f.advancedWordlist))
}

func (f *EnhancedFuzzer) testPayloadAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Test for different vulnerability types
	if vulns := f.testForXSSAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForSQLiAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForCommandInjectionAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForPathTraversalAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForSSRFAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForPrototypePollution(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	if vulns := f.testForOpenRedirectAdvanced(urlStr, payload); len(vulns) > 0 {
		vulnerabilities = append(vulnerabilities, vulns...)
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForXSSAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced XSS testing with modern payloads
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for reflected XSS
	body := string(response.Body)
	if strings.Contains(body, payload) {
		// Check if payload was not properly encoded
		if !strings.Contains(body, f.htmlEncode(payload)) {
			vuln := Vulnerability{
				Type:        "Reflected XSS",
				URL:         urlStr,
				Severity:    "High",
				Description: "Cross-Site Scripting vulnerability detected",
				Payload:     payload,
				CWE:         "CWE-79",
				CVSS:        8.1,
				Remediation: "Implement proper output encoding and input validation",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForSQLiAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced SQL injection testing
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for SQL error messages in response
	sqlErrors := []string{
		"SQL syntax", "MySQL server", "ORA-01756", "PostgreSQL", "SQLite",
		"Microsoft OLE DB", "ODBC Driver", "JDBC Driver", "syntax error",
		"unclosed quotation mark", "quoted string not properly terminated",
	}
	
	body := strings.ToLower(string(response.Body))
	for _, errorMsg := range sqlErrors {
		if strings.Contains(body, strings.ToLower(errorMsg)) {
			vuln := Vulnerability{
				Type:        "SQL Injection",
				URL:         urlStr,
				Severity:    "High",
				Description: "SQL Injection vulnerability detected based on error messages",
				Payload:     payload,
				CWE:         "CWE-89",
				CVSS:        8.8,
				Remediation: "Use parameterized queries/prepared statements and input validation",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForCommandInjectionAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced command injection testing
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for command execution indicators
	cmdIndicators := []string{
		"bin/bash", "bin/sh", "cmd.exe", "command.com", "whoami", "id",
		"root", "administrator", "nt authority", "linux", "windows",
	}
	
	body := strings.ToLower(string(response.Body))
	for _, indicator := range cmdIndicators {
		if strings.Contains(body, indicator) {
			vuln := Vulnerability{
				Type:        "Command Injection",
				URL:         urlStr,
				Severity:    "High",
				Description: "Command Injection vulnerability detected",
				Payload:     payload,
				CWE:         "CWE-78",
				CVSS:        9.1,
				Remediation: "Use proper input validation and avoid passing user input to system commands",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForPathTraversalAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced path traversal testing
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for sensitive file contents
	sensitivePatterns := []string{
		"root:", "etc/passwd", "boot.ini", "windows/win.ini", "SECURITY",
		"SAM", "system32/config", "proc/self/environ", "etc/shadow",
	}
	
	body := string(response.Body)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(body, pattern) {
			vuln := Vulnerability{
				Type:        "Path Traversal",
				URL:         urlStr,
				Severity:    "High",
				Description: "Path Traversal vulnerability detected",
				Payload:     payload,
				CWE:         "CWE-22",
				CVSS:        7.5,
				Remediation: "Implement proper input validation and avoid using user input in file paths",
				References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForSSRFAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced SSRF testing with callback verification
	// This would require an external callback server to verify requests
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForPrototypePollution(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Prototype pollution testing
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for prototype pollution indicators
	if strings.Contains(string(response.Body), "test") && 
	   (strings.Contains(payload, "__proto__") || strings.Contains(payload, "constructor")) {
		vuln := Vulnerability{
			Type:        "Prototype Pollution",
			URL:         urlStr,
			Severity:    "High",
			Description: "Prototype Pollution vulnerability detected",
			Payload:     payload,
			CWE:         "CWE-1321",
			CVSS:        8.1,
			Remediation: "Validate and sanitize all input objects, use Object.create(null) for safe objects",
			References:  []string{"https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf"},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) testForOpenRedirectAdvanced(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Advanced open redirect testing
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for redirect headers
	if location := response.Header.Get("Location"); location != "" {
		// Check if the redirect goes to an external domain
		if parsedURL, err := url.Parse(location); err == nil {
			originalURL, _ := url.Parse(urlStr)
			if parsedURL.Host != "" && parsedURL.Host != originalURL.Host {
				vuln := Vulnerability{
					Type:        "Open Redirect",
					URL:         urlStr,
					Severity:    "Medium",
					Description: "Open Redirect vulnerability detected",
					Payload:     payload,
					CWE:         "CWE-601",
					CVSS:        6.1,
					Remediation: "Validate redirect URLs and use allowlists for trusted domains",
					References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"},
				}
				vulnerabilities = append(vulnerabilities, vuln)
			}
		}
	}
	
	return vulnerabilities
}

func (f *EnhancedFuzzer) htmlEncode(s string) string {
	// Basic HTML encoding
	return strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	).Replace(s)
}
