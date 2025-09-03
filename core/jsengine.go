package core

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/sabbir-lite-0/acva/utils"
)

type JSEngine struct {
	logger   *utils.Logger
	config   utils.Config
}

func NewJSEngine(logger *utils.Logger, config utils.Config) *JSEngine {
	return &JSEngine{
		logger: logger,
		config: config,
	}
}

func (j *JSEngine) AnalyzeSPA(url string) ([]Vulnerability, error) {
	j.logger.Info("Analyzing SPA: %s", url)
	
	var vulnerabilities []Vulnerability
	
	// Create context
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent(j.config.JavaScript.UserAgent),
		chromedp.Flag("headless", j.config.JavaScript.Headless),
		chromedp.WindowSize(j.config.JavaScript.ViewportWidth, j.config.JavaScript.ViewportHeight),
	)
	
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()
	
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	
	ctx, cancel = context.WithTimeout(ctx, time.Duration(j.config.JavaScript.Timeout)*time.Second)
	defer cancel()

	// Run tasks
	var links []string
	var forms []string
	var endpoints []string
	var localStorageData map[string]string
	var cookies []*network.Cookie
	
	// Listen for network events
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventResponseReceived:
			endpoints = append(endpoints, ev.Response.URL)
		}
	})
	
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
		chromedp.Sleep(time.Duration(j.config.JavaScript.WaitFor)*time.Second),
		
		// Extract links
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('a')).map(a => a.href);
		`, &links),
		
		// Extract forms
		chromedp.Evaluate(`
			Array.from(document.querySelectorAll('form')).map(f => ({
				action: f.action,
				method: f.method,
				inputs: Array.from(f.elements).map(i => i.name)
			}));
		`, &forms),
		
		// Extract localStorage
		chromedp.Evaluate(`
			let data = {};
			for (let i = 0; i < localStorage.length; i++) {
				let key = localStorage.key(i);
				data[key] = localStorage.getItem(key);
			}
			data;
		`, &localStorageData),
		
		// Extract cookies
		chromedp.Evaluate(`
			document.cookie.split(';').map(c => c.trim());
		`, &cookies),
		
		// Monitor AJAX calls and API endpoints
		chromedp.Evaluate(`
			window._acvaEndpoints = new Set();
			const originalFetch = window.fetch;
			window.fetch = function(...args) {
				window._acvaEndpoints.add(args[0]);
				return originalFetch.apply(this, args);
			};
			const originalXHR = window.XMLHttpRequest;
			window.XMLHttpRequest = function() {
				const xhr = new originalXHR();
				const open = xhr.open;
				xhr.open = function(method, url) {
					window._acvaEndpoints.add(url);
					return open.apply(this, arguments);
				};
				return xhr;
			};
		`, nil),
		
		// Execute custom scripts if enabled
		chromedp.Evaluate(j.getCustomScripts(), nil),
		
		// Wait for more requests
		chromedp.Sleep(5*time.Second),
		
		// Get collected endpoints
		chromedp.Evaluate(`
			Array.from(window._acvaEndpoints);
		`, &endpoints),
	)
	
	if err != nil {
		return vulnerabilities, err
	}

	// Process results
	allEndpoints := append(links, endpoints...)
	analyzer := NewAnalyzer(j.logger, j.config, utils.NewHTTPClient(j.config.Scan.Timeout), nil)
	pageVulns, err := analyzer.Analyze(allEndpoints, nil)
	if err != nil {
		j.logger.Error("Failed to analyze endpoints: %v", err)
	} else {
		vulnerabilities = append(vulnerabilities, pageVulns...)
	}
	
	// Check for client-side vulnerabilities
	clientSideVulns := j.checkClientSideVulnerabilities(localStorageData, cookies)
	vulnerabilities = append(vulnerabilities, clientSideVulns...)
	
	return vulnerabilities, err
}

func (j *JSEngine) getCustomScripts() string {
	scripts := `
		// Try to trigger common client-side vulnerabilities
		try {
			// Check for AngularJS sandbox escape
			if (typeof angular !== 'undefined') {
				window._acvaAngular = true;
			}
			
			// Check for Vue.js
			if (typeof Vue !== 'undefined') {
				window._acvaVue = true;
			}
			
			// Check for React
			if (typeof React !== 'undefined') {
				window._acvaReact = true;
			}
			
			// Check for jQuery
			if (typeof jQuery !== 'undefined') {
				window._acvaJQuery = true;
			}
			
			// Check for eval usage
			window._acvaEval = typeof eval === 'function';
			
			// Check for innerHTML usage
			window._acvaInnerHTML = document.documentElement.innerHTML.includes('innerHTML');
			
			// Check for postMessage usage
			window.addEventListener('message', function(e) {
				window._acvaPostMessage = true;
				window._acvaPostMessageOrigin = e.origin;
				window._acvaPostMessageData = e.data;
			});
			
			// Try to send a message to ourselves
			window.postMessage('acva_test', '*');
			
		} catch (e) {
			console.error('ACVA script error:', e);
		}
	`
	
	return scripts
}

func (j *JSEngine) checkClientSideVulnerabilities(localStorage map[string]string, cookies []*network.Cookie) []Vulnerability {
	var vulnerabilities []Vulnerability
	
	// Check localStorage for sensitive data
	for key, value := range localStorage {
		if j.isSensitiveData(key, value) {
			vuln := Vulnerability{
				Type:        "Sensitive Data in localStorage",
				URL:         "client-side",
				Severity:    "Medium",
				Description: "Sensitive data stored in localStorage",
				Payload:     key + ": " + value,
				CWE:         "CWE-312",
				CVSS:        5.3,
				Remediation: "Avoid storing sensitive data in localStorage, use secure HTTP-only cookies instead",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Information_exposure_through_client-side_storage"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	// Check cookies for security attributes
	for _, cookie := range cookies {
		if !cookie.Secure && strings.Contains(cookie.Name, "session") {
			vuln := Vulnerability{
				Type:        "Cookie without Secure Flag",
				URL:         "client-side",
				Severity:    "Medium",
				Description: "Session cookie without Secure flag",
				Payload:     cookie.Name,
				CWE:         "CWE-614",
				CVSS:        5.4,
				Remediation: "Set Secure flag on all session cookies",
				References:  []string{"https://owasp.org/www-community/controls/SecureFlag"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
		
		if !cookie.HTTPOnly && strings.Contains(cookie.Name, "session") {
			vuln := Vulnerability{
				Type:        "Cookie without HttpOnly Flag",
				URL:         "client-side",
				Severity:    "Medium",
				Description: "Session cookie without HttpOnly flag",
				Payload:     cookie.Name,
				CWE:         "CWE-1004",
				CVSS:        5.4,
				Remediation: "Set HttpOnly flag on all session cookies",
				References:  []string{"https://owasp.org/www-community/HttpOnly"},
			}
			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	
	return vulnerabilities
}

func (j *JSEngine) isSensitiveData(key, value string) bool {
	sensitivePatterns := []string{
		"token", "auth", "secret", "password", "key", 
		"credential", "session", "jwt", "api_key",
	}
	
	keyLower := strings.ToLower(key)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(keyLower, pattern) {
			return true
		}
	}
	
	return false
}
