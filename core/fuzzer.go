package core

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
)

type Fuzzer struct {
	logger       *utils.Logger
	config       utils.Config
	client       *utils.HTTPClient
	wordlist     []string
	geminiClient *GeminiClient
}

func NewFuzzer(logger *utils.Logger, config utils.Config, client *utils.HTTPClient, geminiClient *GeminiClient) *Fuzzer {
	fuzzer := &Fuzzer{
		logger:       logger,
		config:       config,
		client:       client,
		geminiClient: geminiClient,
	}
	
	// Load wordlists
	fuzzer.loadWordlists()
	
	return fuzzer
}

func (f *Fuzzer) Fuzz(endpoints []string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	f.logger.Info("Starting fuzzing with %d payloads across %d endpoints", len(f.wordlist), len(endpoints))
	
	// Create a worker pool for concurrent fuzzing
	pool := utils.NewWorkerPool(f.config.Scan.ConcurrentRequests, f.config.Scan.Retries, 
		time.Duration(f.config.Scan.Delay)*time.Millisecond)
	
	results := make(chan []Vulnerability, len(endpoints)*len(f.wordlist))
	
	totalTests := len(endpoints) * len(f.wordlist)
	if progress != nil {
		progress.AddTask("Fuzzing endpoints", totalTests)
	}
	
	for _, endpoint := range endpoints {
		for _, payload := range f.wordlist {
			endpoint, payload := endpoint, payload
			
			pool.Submit(func() error {
				fuzzedURLs := f.generateFuzzedURLs(endpoint, payload)
				for _, fuzzedURL := range fuzzedURLs {
					vulns := f.testPayload(fuzzedURL, payload)
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

func (f *Fuzzer) loadWordlists() {
	var allWords []string
	
	// Load from configured wordlists
	for _, wordlistFile := range f.config.Fuzzing.Wordlists {
		if words, err := f.loadWordlist(wordlistFile); err == nil {
			allWords = append(allWords, words...)
		}
	}
	
	// Add built-in payloads
	builtInPayloads := []string{
		"'", "\"", "<script>alert(1)</script>", "${7*7}", "{{7*7}}",
		"../../../etc/passwd", "<!--#exec cmd=\"id\"-->", "|id", ";id",
		"`id`", "$(id)", "{{7*'7'}}", "<%= 7*7 %>", "#{7*7}",
	}
	
	allWords = append(allWords, builtInPayloads...)
	
	// Add payloads from config
	allWords = append(allWords, f.config.Fuzzing.Payloads...)
	
	// Remove duplicates
	f.wordlist = f.removeDuplicates(allWords)
	f.logger.Info("Loaded %d fuzzing payloads", len(f.wordlist))
}

func (f *Fuzzer) loadWordlist(filename string) ([]string, error) {
	var words []string
	
	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		f.logger.Warning("Wordlist file not found: %s", filename)
		return words, err
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return words, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	
	return words, scanner.Err()
}

func (f *Fuzzer) generateFuzzedURLs(endpoint, payload string) []string {
	var fuzzedURLs []string
	
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fuzzedURLs
	}
	
	// Fuzz query parameters
	query := parsed.Query()
	for param := range query {
		fuzzedQuery := query.Clone()
		fuzzedQuery.Set(param, payload)
		parsed.RawQuery = fuzzedQuery.Encode()
		fuzzedURLs = append(fuzzedURLs, parsed.String())
	}
	
	// Fuzz path segments
	if strings.Contains(parsed.Path, "/") {
		pathSegments := strings.Split(parsed.Path, "/")
		for i, segment := range pathSegments {
			if segment != "" {
				fuzzedPath := make([]string, len(pathSegments))
				copy(fuzzedPath, pathSegments)
				fuzzedPath[i] = payload
				parsed.Path = strings.Join(fuzzedPath, "/")
				fuzzedURLs = append(fuzzedURLs, parsed.String())
			}
		}
	}
	
	// Add payload as new parameter
	parsed.RawQuery = parsed.Query().Encode() + "&test=" + url.QueryEscape(payload)
	fuzzedURLs = append(fuzzedURLs, parsed.String())
	
	return fuzzedURLs
}

func (f *Fuzzer) testPayload(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Test for different vulnerability types
	if f.config.Vulnerabilities.SQLInjection {
		if vulns := f.testForSQLi(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	if f.config.Vulnerabilities.XSS {
		if vulns := f.testForXSS(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	if f.config.Vulnerabilities.CommandInjection {
		if vulns := f.testForCommandInjection(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	if f.config.Vulnerabilities.PathTraversal {
		if vulns := f.testForPathTraversal(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	if f.config.Vulnerabilities.SSRF {
		if vulns := f.testForSSRF(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	return vulnerabilities
}

func (f *Fuzzer) testForSQLi(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
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
	
	body := strings.ToLower(response)
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

func (f *Fuzzer) testForXSS(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for reflected XSS
	if strings.Contains(response, payload) {
		// Check if payload was not properly encoded
		if !strings.Contains(response, f.htmlEncode(payload)) {
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

func (f *Fuzzer) testForCommandInjection(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for command execution indicators
	cmdIndicators := []string{
		"bin/bash", "bin/sh", "cmd.exe", "command.com", "whoami", "id",
		"root", "administrator", "nt authority", "linux", "windows",
	}
	
	body := strings.ToLower(response)
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

func (f *Fuzzer) testForPathTraversal(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for sensitive file contents
	sensitivePatterns := []string{
		"root:", "etc/passwd", "boot.ini", "windows/win.ini", "SECURITY",
		"SAM", "system32/config", "proc/self/environ", "etc/shadow",
	}
	
	for _, pattern := range sensitivePatterns {
		if strings.Contains(response, pattern) {
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

func (f *Fuzzer) testForSSRF(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// SSRF testing would typically involve:
	// 1. Testing for URL-based parameters that might trigger external requests
	// 2. Checking if the server makes requests to internal resources
	// 3. Testing for DNS rebinding attacks
	
	// This is a placeholder implementation
	// In a real implementation, you would use a callback server to detect SSRF
	
	return vulnerabilities
}

func (f *Fuzzer) htmlEncode(s string) string {
	// Basic HTML encoding
	return strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
	).Replace(s)
}

func (f *Fuzzer) removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}
