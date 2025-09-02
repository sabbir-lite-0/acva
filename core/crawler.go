package core

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
	"golang.org/x/net/html"
)

type Crawler struct {
	baseURL     string
	logger      *utils.Logger
	config      utils.Config
	visitedURLs map[string]bool
	urlMutex    sync.Mutex
	client      *utils.HTTPClient
}

func NewCrawler(logger *utils.Logger, config utils.Config, client *utils.HTTPClient) *Crawler {
	return &Crawler{
		logger:      logger,
		config:      config,
		visitedURLs: make(map[string]bool),
		client:      client,
	}
}

func (c *Crawler) Crawl(baseURL string) ([]string, error) {
	c.baseURL = baseURL
	c.logger.Info("Crawling %s with depth %d", c.baseURL, c.config.Scan.Depth)
	
	var allEndpoints []string
	queue := []string{c.baseURL}
	depth := 0
	
	for len(queue) > 0 && depth <= c.config.Scan.Depth && len(allEndpoints) < c.config.Scan.MaxPages {
		currentURL := queue[0]
		queue = queue[1:]
		
		if c.isVisited(currentURL) {
			continue
		}
		
		c.markVisited(currentURL)
		
		// Fetch page content
		body, err := c.client.Get(currentURL)
		if err != nil {
			c.logger.Debug("Failed to fetch %s: %v", currentURL, err)
			continue
		}
		
		// Extract links from HTML
		links := c.extractLinks(body, currentURL)
		
		// Find API endpoints in JavaScript
		apiEndpoints := c.findAPIEndpoints(body)
		
		// Find forms and their action URLs
		formEndpoints := c.extractFormActions(body, currentURL)
		
		// Combine all endpoints
		pageEndpoints := append(links, apiEndpoints...)
		pageEndpoints = append(pageEndpoints, formEndpoints...)
		
		// Clean and filter endpoints
		cleanEndpoints := c.cleanEndpoints(pageEndpoints)
		
		// Add to results
		allEndpoints = append(allEndpoints, cleanEndpoints...)
		
		// Add new URLs to queue for next depth level
		for _, endpoint := range cleanEndpoints {
			if !c.isVisited(endpoint) && c.isSameDomain(endpoint) {
				queue = append(queue, endpoint)
			}
		}
		
		depth++
		
		// Respect delay between requests
		if c.config.Scan.Delay > 0 {
			time.Sleep(time.Duration(c.config.Scan.Delay) * time.Millisecond)
		}
	}
	
	// Remove duplicates
	allEndpoints = c.removeDuplicates(allEndpoints)
	
	c.logger.Info("Found %d unique endpoints", len(allEndpoints))
	return allEndpoints, nil
}

func (c *Crawler) extractLinks(htmlContent, baseURL string) []string {
	var links []string
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		c.logger.Debug("Failed to parse HTML: %v", err)
		return links
	}
	
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, attr := range n.Attr {
				if attr.Key == "href" {
					links = append(links, c.resolveURL(attr.Val, baseURL))
					break
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(doc)
	
	return links
}

func (c *Crawler) extractFormActions(htmlContent, baseURL string) []string {
	var actions []string
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return actions
	}
	
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					actions = append(actions, c.resolveURL(attr.Val, baseURL))
					break
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			f(child)
		}
	}
	f(doc)
	
	return actions
}

func (c *Crawler) findAPIEndpoints(htmlContent string) []string {
	var endpoints []string
	patterns := []string{
		`fetch\(["']([^"']+)["']`,
		`axios\.(get|post|put|delete)\(["']([^"']+)["']`,
		`\.ajax\([^)]*url:["']([^"']+)["']`,
		`API_URL\s*=\s*["']([^"']+)["']`,
		`window\.location\.href\s*=\s*["']([^"']+)["']`,
		`\.open\(["'](GET|POST|PUT|DELETE)["'],\s*["']([^"']+)["']`,
	}
	
	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllStringSubmatch(htmlContent, -1)
		
		for _, match := range matches {
			if len(match) > 1 {
				// For patterns with method and URL, the URL is in the last group
				endpoint := match[len(match)-1]
				if !strings.HasPrefix(endpoint, "http") {
					endpoint = c.resolveURL(endpoint, c.baseURL)
				}
				endpoints = append(endpoints, endpoint)
			}
		}
	}
	
	return endpoints
}

func (c *Crawler) resolveURL(relativeURL, baseURL string) string {
	if strings.HasPrefix(relativeURL, "http") {
		return relativeURL
	}
	
	base, err := url.Parse(baseURL)
	if err != nil {
		return relativeURL
	}
	
	rel, err := url.Parse(relativeURL)
	if err != nil {
		return relativeURL
	}
	
	return base.ResolveReference(rel).String()
}

func (c *Crawler) cleanEndpoints(endpoints []string) []string {
	var cleanEndpoints []string
	seen := make(map[string]bool)
	
	for _, endpoint := range endpoints {
		// Skip invalid URLs
		if _, err := url.ParseRequestURI(endpoint); err != nil {
			continue
		}
		
		// Remove fragments
		if strings.Contains(endpoint, "#") {
			endpoint = strings.Split(endpoint, "#")[0]
		}
		
		// Remove common tracking parameters
		endpoint = removeTrackingParams(endpoint)
		
		// Normalize URL
		endpoint = strings.TrimRight(endpoint, "/")
		
		if !seen[endpoint] && c.isSameDomain(endpoint) {
			seen[endpoint] = true
			cleanEndpoints = append(cleanEndpoints, endpoint)
		}
	}
	
	return cleanEndpoints
}

func removeTrackingParams(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	
	query := parsed.Query()
	// Remove common tracking parameters
	trackingParams := []string{"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", 
		"fbclid", "gclid", "msclkid", "dclid", "mc_cid", "mc_eid"}
	
	for _, param := range trackingParams {
		query.Del(param)
	}
	
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func (c *Crawler) isSameDomain(urlStr string) bool {
	target, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	
	base, err := url.Parse(c.baseURL)
	if err != nil {
		return false
	}
	
	return target.Hostname() == base.Hostname()
}

func (c *Crawler) isVisited(url string) bool {
	c.urlMutex.Lock()
	defer c.urlMutex.Unlock()
	return c.visitedURLs[url]
}

func (c *Crawler) markVisited(url string) {
	c.urlMutex.Lock()
	defer c.urlMutex.Unlock()
	c.visitedURLs[url] = true
}

func (c *Crawler) removeDuplicates(urls []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, url := range urls {
		if !seen[url] {
			seen[url] = true
			result = append(result, url)
		}
	}
	
	return result
}
