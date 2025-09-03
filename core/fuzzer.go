package core

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
	"github.com/sabbir-lite-0/acva/core/gemini"
)

type Fuzzer struct {
	logger       *utils.Logger
	config       utils.Config
	client       *utils.HTTPClient
	wordlist     []string
	geminiClient *gemini.GeminiClient
}

func NewFuzzer(logger *utils.Logger, config utils.Config, client *utils.HTTPClient, geminiClient *gemini.GeminiClient) *Fuzzer {
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

func (f *Fuzzer) loadWordlists() {
	var allWords []string
	
	// Load from configured wordlists
	for _, wordlistFile := range f.config.Fuzzing.Wordlists {
		if words, err := f.loadWordlist(wordlistFile); err == nil {
			allWords = append(allWords, words...)
			f.logger.Info("Loaded %d words from %s", len(words), wordlistFile)
		} else {
			f.logger.Warning("Failed to load wordlist %s: %v", wordlistFile, err)
		}
	}
	
	// Add built-in payloads
	allWords = append(allWords, f.config.Fuzzing.Payloads...)
	
	// Use Gemini to generate advanced payloads if enabled
	if f.geminiClient != nil && f.config.Gemini.Enabled {
		f.logger.Info("Generating advanced payloads with Gemini AI...")
		
		// Generate payloads for different vulnerability types
		vulnTypes := []string{"SQL Injection", "XSS", "Path Traversal", "Command Injection"}
		
		for _, vulnType := range vulnTypes {
			payloads, err := f.geminiClient.GenerateAdvancedPayloads(vulnType, "Web application security testing")
			if err != nil {
				f.logger.Warning("Failed to generate %s payloads: %v", vulnType, err)
				continue
			}
			
			allWords = append(allWords, payloads...)
			f.logger.Info("Generated %d %s payloads", len(payloads), vulnType)
		}
	}
	
	// Remove duplicates
	f.wordlist = utils.RemoveDuplicates(allWords)
	f.logger.Info("Total unique payloads: %d", len(f.wordlist))
}

func (f *Fuzzer) loadWordlist(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}

	return words, scanner.Err()
}

func (f *Fuzzer) Fuzz(endpoints []string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	f.logger.Info("Fuzzing %d endpoints with %d payloads", len(endpoints), len(f.wordlist))
	
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

func (f *Fuzzer) generateFuzzedURLs(originalURL, payload string) []string {
	var fuzzedURLs []string
	
	parsed, err := url.Parse(originalURL)
	if err != nil {
		return fuzzedURLs
	}
	
	// Fuzz query parameters
	query := parsed.Query()
	for param := range query {
		// Manual clone of url.Values
		fuzzedQuery := make(url.Values)
		for k, v := range query {
			fuzzedQuery[k] = v
		}
		fuzzedQuery.Set(param, payload)
		parsed.RawQuery = fuzzedQuery.Encode()
		fuzzedURLs = append(fuzzedURLs, parsed.String())
	}
	
	// Add new parameter
	newParamQuery := make(url.Values)
	for k, v := range query {
		newParamQuery[k] = v
	}
	newParamQuery.Set("fuZZ_"+payload, payload)
	parsed.RawQuery = newParamQuery.Encode()
	fuzzedURLs = append(fuzzedURLs, parsed.String())
	
	// Fuzz path
	if strings.Contains(parsed.Path, "/") {
		pathParts := strings.Split(parsed.Path, "/")
		for i, part := range pathParts {
			if part != "" {
				originalPart := pathParts[i]
				pathParts[i] = payload
				parsed.Path = strings.Join(pathParts, "/")
				fuzzedURLs = append(fuzzedURLs, parsed.String())
				pathParts[i] = originalPart
			}
		}
	}
	
	// Add payload to end of path
	parsed.Path = parsed.Path + "/" + payload
	fuzzedURLs = append(fuzzedURL極, parsed.String())
	
	return fuzzedURLs
}

func (f *Fuzzer) testPayload(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Test for SQL injection
	if f.config.Vulnerabilities.SQLInjection {
		if vulns := f.testForSQLi(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Test for XSS
	if f.config.Vulnerabilities.XSS {
		if vulns := f.testForXSS(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Test for command injection
	if f.config.Vulnerabilities.CommandInjection {
		if vulns := f.testForCommandInjection(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Test for path traversal
	if f.config.Vulnerabilities.PathTraversal {
		if vulns := f.testForPathTraversal(urlStr, payload); len(vulns) > 0 {
			vulnerabilities = append(vulnerabilities, vulns...)
		}
	}
	
	// Test for SSRF
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
		"sql syntax", "syntax error", "mysql", "ora-", "postgresql",
		"microsoft ole db", "odbc driver", "jdbc driver", 
		"unclosed quotation mark", "quoted string not properly terminated",
	}
	
	body := strings.ToLower(response)
	for _, errorMsg := range sqlErrors {
		if strings.Contains(body, errorMsg) {
			vuln := Vulnerability{
				Type:        "SQL Injection",
				URL:         urlStr,
				Severity:    "High",
				Description: "Potential SQL Injection vulnerability detected",
				Payload:     payload,
				CWE:         "CWE-89",
				CVSS:        8.8,
				Remediation: "Use parameterized queries/prepared statements and input validation",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
			}
			
			// AI confirmation if available
			if f.geminiClient != nil {
				confirmed, reason, err := f.geminiClient.AnalyzeResponse(response, payload, "SQL Injection")
				if err == nil && confirmed {
					vuln.Description = "AI-confirmed SQL Injection: " + reason
					vuln.Evidence = response
				}
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
	
	// Check if payload is reflected in response
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
			
			// AI confirmation if available
			if f.geminiClient != nil {
				confirmed, reason, err := f.geminiClient.AnalyzeResponse(response, payload, "XSS")
				if err == nil && confirmed {
					vuln.Description = "AI-confirmed XSS: " + reason
					vuln.Evidence = response
				}
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
			
			// AI confirmation if available
			if f.geminiClient != nil {
				confirmed, reason, err := f.geminiClient.AnalyzeResponse(response, payload, "Command Injection")
				if err == nil && confirmed {
					vuln.Description = "AI-confirmed Command Injection: " + reason
					vuln.Evidence = response
				}
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
			
			// AI confirmation if available
			if f.geminiClient != nil {
				confirmed, reason, err := f.geminiClient.AnalyzeResponse(response, payload, "Path Traversal")
				if err == nil && confirmed {
					vuln.Description = "AI-confirmed Path Traversal: " + reason
					vuln.Evidence = response
				}
			}
			
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
	return vulnerabilities
}

func (f *Fuzzer) testForSSRF(urlStr, payload string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// SSRF testing requires special handling with callback server
	// This is a simplified version
	
	response, err := f.client.Get(urlStr)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for internal IP addresses or cloud metadata in response
	internalPatterns := []string{
		"192.168.", "10.", "172.16.", "127.0.0.1", "localhost",
		"169.254.169.254", "metadata.google.internal",
	}
	
	for _, pattern := range internalPatterns {
		if strings.Contains(response, pattern) {
			vuln := Vulnerability{
				Type:        "SSRF",
				URL:         urlStr,
				Severity:    "High",
				Description: "Server-Side Request Forgery vulnerability detected",
				Payload:     payload,
				CWE:         "CWE-918",
				CVSS:        8.1,
				Remediation: "Validate and sanitize all user input used in URL generation",
				References:  []string{"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
			}
			
			// AI confirmation if available
			if f.geminiClient != nil {
				confirmed, reason, err := f.geminiClient.AnalyzeResponse(response, payload, "SSRF")
				if err == nil && confirmed {
					vuln.Description = "AI-confirmed SSRF: " + reason
					vuln.Evidence = response
				}
			}
			
			vulnerabilities = append(vulnerabilities, vuln)
			break
		}
	}
	
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
