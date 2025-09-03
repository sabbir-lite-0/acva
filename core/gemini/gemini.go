package gemini

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
)

type GeminiClient struct {
	apiKeys    []string
	currentKey int
	model      string
	baseURL    string
	logger     *utils.Logger
	httpClient *http.Client
	keyMutex   sync.Mutex
	usageCount map[string]int
	maxRetries int
	rateLimit  time.Duration
}

type GeminiRequest struct {
	Contents []Content `json:"contents"`
}

type Content struct {
	Parts []Part `json:"parts"`
}

type Part struct {
	Text string `json:"text"`
}

type GeminiResponse struct {
	Candidates []Candidate  `json:"candidates"`
	Error      *GeminiError `json:"error,omitempty"`
}

type Candidate struct {
	Content Content `json:"content"`
}

type GeminiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

func NewGeminiClient(apiKeys []string, model string, logger *utils.Logger) *GeminiClient {
	if len(apiKeys) == 0 {
		logger.Warning("No Gemini API keys provided")
		return nil
	}

	usageCount := make(map[string]int)
	for _, key := range apiKeys {
		usageCount[key] = 0
	}

	return &GeminiClient{
		apiKeys:    apiKeys,
		currentKey: 0,
		model:      model,
		baseURL:    "https://generativelanguage.googleapis.com/v1beta/models/",
		logger:     logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				DisableKeepAlives:   false,
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
		usageCount: usageCount,
		maxRetries: len(apiKeys) * 3,
		rateLimit:  100 * time.Millisecond, // 10 requests per second
	}
}

func (g *GeminiClient) getCurrentKey() string {
	g.keyMutex.Lock()
	defer g.keyMutex.Unlock()
	return g.apiKeys[g.currentKey]
}

func (g *GeminiClient) rotateKey() {
	g.keyMutex.Lock()
	defer g.keyMutex.Unlock()
	g.currentKey = (g.currentKey + 1) % len(g.apiKeys)
	g.logger.Debug("Rotated to Gemini API key index: %d", g.currentKey)
}

func (g *GeminiClient) incrementUsage(key string) {
	g.keyMutex.Lock()
	defer g.keyMutex.Unlock()
	g.usageCount[key]++
}

func (g *GeminiClient) getUsageCount(key string) int {
	g.keyMutex.Lock()
	defer g.keyMutex.Unlock()
	return g.usageCount[key]
}

func (g *GeminiClient) GenerateAdvancedPayloads(vulnType, context string) ([]string, error) {
	prompt := fmt.Sprintf(`Generate advanced exploitation payloads for %s vulnerability. 
	Context: %s
	Consider WAF bypass techniques, obfuscation, and modern exploitation methods.
	Return only a JSON array of payload strings without any additional text.`, vulnType, context)

	response, err := g.makeRequestWithRetry(prompt)
	if err != nil {
		return nil, err
	}

	var payloads []string
	for _, candidate := range response.Candidates {
		for _, part := range candidate.Content.Parts {
			// Clean the response and extract JSON
			cleanText := strings.TrimSpace(part.Text)
			cleanText = strings.TrimPrefix(cleanText, "```json")
			cleanText = strings.TrimSuffix(cleanText, "```")
			cleanText = strings.TrimSpace(cleanText)
			
			if strings.HasPrefix(cleanText, "[") && strings.HasSuffix(cleanText, "]") {
				err := json.Unmarshal([]byte(cleanText), &payloads)
				if err != nil {
					g.logger.Error("Failed to parse Gemini response: %v", err)
					continue
				}
				return payloads, nil
			}
		}
	}

	return nil, fmt.Errorf("no valid payloads found in response")
}

func (g *GeminiClient) AnalyzeResponse(responseText, payload, vulnType string) (bool, string, error) {
	// Truncate very long responses to avoid token limits
	if len(responseText) > 8000 {
		responseText = responseText[:8000] + "...(truncated)"
	}

	prompt := fmt.Sprintf(`Analyze this web response for %s vulnerability. 
	Payload used: %s
	Response: %s
	
	Return JSON with this exact structure:
	{
		"confirmed": boolean,
		"confidence": "high/medium/low",
		"reason": "string explaining why"
	}`, vulnType, payload, responseText)

	geminiResponse, err := g.makeRequestWithRetry(prompt)
	if err != nil {
		return false, "", err
	}

	for _, candidate := range geminiResponse.Candidates {
		for _, part := range candidate.Content.Parts {
			// Clean the response
			cleanText := strings.TrimSpace(part.Text)
			cleanText = strings.TrimPrefix(cleanText, "```json")
			cleanText = strings.TrimSuffix(cleanText, "```")
			cleanText = strings.TrimSpace(cleanText)
			
			var result struct {
				Confirmed  bool   `json:"confirmed"`
				Confidence string `json:"confidence"`
				Reason     string `json:"reason"`
			}
			
			if err := json.Unmarshal([]byte(cleanText), &result); err != nil {
				g.logger.Debug("Failed to unmarshal analysis result: %v", err)
				continue
			}
			
			return result.Confirmed, result.Reason, nil
		}
	}

	return false, "No analysis result found", nil
}

func (g *GeminiClient) makeRequestWithRetry(prompt string) (*GeminiResponse, error) {
	var lastError error
	
	for retry := 0; retry < g.maxRetries; retry++ {
		time.Sleep(g.rateLimit) // Respect rate limit
		
		currentKey := g.getCurrentKey()
		g.logger.Debug("Using Gemini API key index %d (attempt %d/%d)", 
			g.currentKey, retry+1, g.maxRetries)
		
		response, err := g.makeRequest(prompt, currentKey)
		if err == nil {
			g.incrementUsage(currentKey)
			return response, nil
		}
		
		lastError = err
		
		// Check if it's a rate limit error
		if response != nil && response.Error != nil {
			if response.Error.Code == 429 || strings.Contains(response.Error.Message, "quota") ||
				strings.Contains(response.Error.Message, "rate") || strings.Contains(response.Error.Message, "limit") {
				g.logger.Warning("Rate limit exceeded for API key %d, rotating...", g.currentKey)
				g.rotateKey()
				time.Sleep(2 * time.Second) // Wait before retrying
				continue
			}
		}
		
		// For other errors, wait and retry with same key
		time.Sleep(time.Duration(retry+1) * time.Second)
	}
	
	return nil, fmt.Errorf("all retries failed: %v", lastError)
}

func (g *GeminiClient) makeRequest(prompt, apiKey string) (*GeminiResponse, error) {
	url := fmt.Sprintf("%s%s:generateContent?key=%s", g.baseURL, g.model, apiKey)
	
	requestBody := GeminiRequest{
		Contents: []Content{
			{
				Parts: []Part{
					{
						Text: prompt,
					},
				},
			},
		},
	}

	jsonBody, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ACVA-Scanner/1.0")
	
	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var response GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	// Check for API errors
	if response.Error != nil {
		return &response, fmt.Errorf("Gemini API error: %s (code: %d)", response.Error.Message, response.Error.Code)
	}

	return &response, nil
}

func (g *GeminiClient) GetUsageStats() map[string]int {
	g.keyMutex.Lock()
	defer g.keyMutex.Unlock()
	
	stats := make(map[string]int)
	for key, count := range g.usageCount {
		// Mask the API key for security
		maskedKey := fmt.Sprintf("key_%d", strings.LastIndex(key, "_"))
		stats[maskedKey] = count
	}
	return stats
}

// New method for vulnerability explanation
func (g *GeminiClient) ExplainVulnerability(vulnType, details string) (string, error) {
	prompt := fmt.Sprintf(`Explain the %s vulnerability in simple terms.
	Details: %s
	Provide a concise explanation suitable for security reports.`, vulnType, details)

	response, err := g.makeRequestWithRetry(prompt)
	if err != nil {
		return "", err
	}

	for _, candidate := range response.Candidates {
		for _, part := range candidate.Content.Parts {
			return strings.TrimSpace(part.Text), nil
		}
	}

	return "", fmt.Errorf("no explanation found in response")
}
