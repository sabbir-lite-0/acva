package utils

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type HTTPClient struct {
	client         *http.Client
	headers        map[string]string
	cookies        map[string]string
	proxyURL       string
	followRedirects bool
	rateLimiter    *time.Ticker
}

func NewHTTPClient(timeout int) *HTTPClient {
	jar, _ := cookiejar.New(nil)
	
	return &HTTPClient{
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			Jar:     jar,
		},
		headers:        make(map[string]string),
		cookies:        make(map[string]string),
		followRedirects: true,
	}
}

func (c *HTTPClient) Get(url string) (string, error) {
	return c.Request("GET", url, nil, "")
}

func (c *HTTPClient) Post(url, contentType string, body io.Reader) (string, error) {
	return c.Request("POST", url, body, contentType)
}

func (c *HTTPClient) Request(method, urlStr string, body io.Reader, contentType string) (string, error) {
	// Respect rate limiting
	if c.rateLimiter != nil {
		<-c.rateLimiter.C
	}

	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return "", err
	}
	
	// Set headers
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	
	// Set content type if provided
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	
	// Set cookies
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{
			Name:  name,
			Value: value,
		})
	}
	
	// Make the request
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	return string(responseBody), nil
}

func (c *HTTPClient) SetProxy(proxyURL string) {
	c.proxyURL = proxyURL
	
	if proxyURL == "" {
		c.client.Transport = nil
		return
	}
	
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return
	}
	
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	
	c.client.Transport = transport
}

func (c *HTTPClient) SetRedirectPolicy(follow bool) {
	c.followRedirects = follow
	
	if follow {
		c.client.CheckRedirect = nil
	} else {
		c.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
}

func (c *HTTPClient) AddHeader(key, value string) {
	c.headers[key] = value
}

func (c *HTTPClient) AddCookie(name, value string) {
	c.cookies[name] = value
}

func (c *HTTPClient) SetBasicAuth(username, password string) {
	c.headers["Authorization"] = "Basic " + basicAuth(username, password)
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *HTTPClient) SetTimeout(timeout int) {
	c.client.Timeout = time.Duration(timeout) * time.Second
}

func (c *HTTPClient) SetRateLimit(requestsPerSecond int) {
	if requestsPerSecond <= 0 {
		c.rateLimiter = nil
		return
	}
	
	interval := time.Second / time.Duration(requestsPerSecond)
	c.rateLimiter = time.NewTicker(interval)
}

func (c *HTTPClient) GetResponse(urlStr string) (*http.Response, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	
	// Set headers
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	
	return c.client.Do(req)
}
