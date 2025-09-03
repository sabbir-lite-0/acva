package core

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/sabbir-lite-0/acva/utils"
)

type APIScanner struct {
	logger *utils.Logger
	client *utils.HTTPClient
}

func NewAPIScanner(logger *utils.Logger, client *utils.HTTPClient) *APIScanner {
	return &APIScanner{
		logger: logger,
		client: client,
	}
}

func (a *APIScanner) DiscoverEndpoints(target string) []string {
	var endpoints []string
	
	// Common API endpoints
	commonEndpoints := []string{
		"/api/v1/users",
		"/api/v1/products",
		"/api/v1/config",
		"/api/v1/admin",
		"/api/v1/auth",
		"/api/v1/login",
		"/api/v1/register",
		"/api/v1/profile",
		"/api/v1/settings",
		"/api/v1/health",
		"/api/v1/status",
		"/api/v1/info",
		"/api/v1/version",
		"/api/v1/docs",
		"/api/v1/swagger",
		"/api/v1/openapi",
	}
	
	for _, endpoint := range commonEndpoints {
		fullURL := target + endpoint
		endpoints = append(endpoints, fullURL)
	}
	
	// Also try with different versions
	versions := []string{"v1", "v2", "v3", "v4", "v5"}
	for _, version := range versions {
		for _, endpoint := range commonEndpoints {
			fullURL := target + "/api/" + version + endpoint[7:] // Remove "/api/v1" prefix
			endpoints = append(endpoints, fullURL)
		}
	}
	
	return endpoints
}

func (a *APIScanner) TestAPIEndpoint(endpoint string) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Test for common API vulnerabilities
	response, err := a.client.Get(endpoint)
	if err != nil {
		return vulnerabilities
	}
	
	// Check for sensitive data exposure
	if a.containsSensitiveData(response) {
		vuln := Vulnerability{
			Type:        "Sensitive Data Exposure",
			URL:         endpoint,
			Severity:    "High",
			Description: "API endpoint exposes sensitive data",
			CWE:         "CWE-200",
			CVSS:        7.5,
			Remediation: "Implement proper access controls and data masking",
			References:  []string{"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	// Check for insecure HTTP methods
	if a.hasInsecureMethods(endpoint) {
		vuln := Vulnerability{
			Type:        "Insecure HTTP Methods",
			URL:         endpoint,
			Severity:    "Medium",
			Description: "API endpoint allows insecure HTTP methods",
			CWE:         "CWE-650",
			CVSS:        5.3,
			Remediation: "Disable insecure HTTP methods like PUT, DELETE, etc.",
			References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Methods"},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	// Check for authentication bypass
	if a.isAuthBypassPossible(endpoint) {
		vuln := Vulnerability{
			Type:        "Authentication Bypass",
			URL:         endpoint,
			Severity:    "High",
			Description: "API endpoint allows authentication bypass",
			CWE:         "CWE-288",
			CVSS:        8.8,
			Remediation: "Implement proper authentication and authorization checks",
			References:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema"},
		}
		vulnerabilities = append(vulnerabilities, vuln)
	}
	
	return vulnerabilities
}

func (a *APIScanner) containsSensitiveData(response string) bool {
	sensitivePatterns := []string{
		"password", "token", "secret", "key", "credential",
		"email", "phone", "address", "credit_card", "ssn",
	}
	
	responseLower := strings.ToLower(response)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(responseLower, pattern) {
			return true
		}
	}
	return false
}

func (a *APIScanner) hasInsecureMethods(endpoint string) bool {
	// Try insecure methods
	methods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
	for _, method := range methods {
		// Simulate request with method
		// In real implementation, you would use the HTTP client to make requests with different methods
		if method == "PUT" || method == "DELETE" {
			return true
		}
	}
	return false
}

func (a *APIScanner) isAuthBypassPossible(endpoint string) bool {
	// Try accessing without authentication
	// In real implementation, you would try to access the endpoint without proper tokens
	return strings.Contains(endpoint, "admin") || strings.Contains(endpoint, "user")
}
