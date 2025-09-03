package utils

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Scan struct {
		Depth              int               `yaml:"depth"`
		MaxPages           int               `yaml:"max_pages"`
		Timeout            int               `yaml:"timeout"`
		UserAgent          string            `yaml:"user_agent"`
		ConcurrentRequests int               `yaml:"concurrent_requests"`
		Delay              int               `yaml:"delay"`
		Retries            int               `yaml:"retries"`
		Proxy              string            `yaml:"proxy"`
		FollowRedirects    bool              `yaml:"follow_redirects"`
		RateLimit          int               `yaml:"rate_limit"`
		MaxRetries         int               `yaml:"max_retries"`
		BackoffDelay       int               `yaml:"backoff_delay"`
		CustomHeaders      map[string]string `yaml:"custom_headers"`
		CustomCookies      map[string]string `yaml:"custom_cookies"`
		Auth               AuthConfig        `yaml:"auth"`
	} `yaml:"scan"`
	
	Fuzzing struct {
		Wordlists []string `yaml:"wordlists"`
		Payloads  []string `yaml:"payloads"`
	} `yaml:"fuzzing"`
	
	Vulnerabilities struct {
		SQLInjection                   bool `yaml:"sql_injection"`
		XSS                            bool `yaml:"xss"`
		CSRF                           bool `yaml:"csrf"`
		PathTraversal                  bool `yaml:"path_traversal"`
		SensitiveFiles                 bool `yaml:"sensitive_files"`
		JWTSecurity                    bool `yaml:"jwt_security"`
		SSRF                           bool `yaml:"ssrf"`
		CommandInjection               bool `yaml:"command_injection"`
		InsecureDirectObjectReference  bool `yaml:"insecure_direct_object_reference"`
		OpenRedirect                   bool `yaml:"open_redirect"`
		XXE                            bool `yaml:"xxe"`
		InsecureDeserialization        bool `yaml:"insecure_deserialization"`
		SecurityMisconfiguration       bool `yaml:"security_misconfiguration"`
		GraphQLInjection               bool `yaml:"graphql_injection"`
		WebSocketVulnerabilities       bool `yaml:"websocket_vulnerabilities"`
		PrototypePollution             bool `yaml:"prototype_pollution"`
		CloudMisconfigurations         bool `yaml:"cloud_misconfigurations"`
		SubdomainTakeover              bool `yaml:"subdomain_takeover"`
	} `yaml:"vulnerabilities"`
	
	JavaScript struct {
		Enable           bool   `yaml:"enable"`
		Timeout          int    `yaml:"timeout"`
		Headless         bool   `yaml:"headless"`
		UserAgent        string `yaml:"user_agent"`
		WaitFor          int    `yaml:"wait_for"`
		ViewportWidth    int    `yaml:"viewport_width"`
		ViewportHeight   int    `yaml:"viewport_height"`
		ExecuteScripts   bool   `yaml:"execute_scripts"`
		InterceptRequests bool   `yaml:"intercept_requests"`
	} `yaml:"javascript"`
	
	Python struct {
		Enable     bool   `yaml:"enable"`
		SqlmapPath string `yaml:"sqlmap_path"`
		XsserPath  string `yaml:"xsser_path"`
		NucleiPath string `yaml:"nuclei_path"`
		NiktoPath  string `yaml:"nikto_path"`
	} `yaml:"python"`
	
	Reporting struct {
		Formats                []string `yaml:"formats"`
		OutputDir              string   `yaml:"output_dir"`
		IncludeRequestResponse bool     `yaml:"include_request_response"`
		RiskLevel              string   `yaml:"risk_level"`
		Detailed               bool     `yaml:"detailed"`
		ExecutiveSummary       bool     `yaml:"executive_summary"`
		RemediationGuidance    bool     `yaml:"remediation_guidance"`
	} `yaml:"reporting"`
	
	Advanced struct {
		SSRFProbeURL string   `yaml:"ssrf_probe_url"`
		BypassWAF    bool     `yaml:"bypass_waf"`
		Techniques   []string `yaml:"techniques"`
	} `yaml:"advanced"`
	
	Compliance struct {
		Frameworks         []string `yaml:"frameworks"`
		GenerateReports    bool     `yaml:"generate_reports"`
		EnableGDPRCheck    bool     `yaml:"enable_gdpr_check"`
		EnableHIPAACheck   bool     `yaml:"enable_hipaa_check"`
		EnablePCIDSSCheck  bool     `yaml:"enable_pci_dss_check"`
	} `yaml:"compliance"`
	
	Safety struct {
		MaxScanDuration   int      `yaml:"max_scan_duration"`
		BlacklistedIPs    []string `yaml:"blacklisted_ips"`
		WhitelistedDomains []string `yaml:"whitelisted_domains"`
	} `yaml:"safety"`
	
	Logging struct {
		Level      string `yaml:"level"`
		FilePath   string `yaml:"file_path"`
		MaxSize    int    `yaml:"max_size"`
		MaxBackups int    `yaml:"max_backups"`
		MaxAge     int    `yaml:"max_age"`
	} `yaml:"logging"`
	
	API struct {
		Enabled   bool   `yaml:"enabled"`
		Host      string `yaml:"host"`
		Port      int    `yaml:"port"`
		AuthKey   string `yaml:"auth_key"`
		RateLimit int    `yaml:"rate_limit"`
	} `yaml:"api"`
	
	Cluster struct {
		Enabled  bool   `yaml:"enabled"`
		Mode     string `yaml:"mode"`
		RedisURL string `yaml:"redis_url"`
		Workers  int    `yaml:"workers"`
	} `yaml:"cluster"`
	
	Notifications struct {
		Email struct {
			Enabled   bool   `yaml:"enabled"`
			SMTPHost  string `yaml:"smtp_host"`
			SMTPPort  int    `yaml:"smtp_port"`
			SMTPUser  string `yaml:"smtp_user"`
			SMTPPass  string `yaml:"smtp_pass"`
			From      string `yaml:"from"`
			To        string `yaml:"to"`
		} `yaml:"email"`
		Slack struct {
			Enabled    bool   `yaml:"enabled"`
			WebhookURL string `yaml:"webhook_url"`
		} `yaml:"slack"`
		Webhook struct {
			Enabled bool   `yaml:"enabled"`
			URL     string `yaml:"url"`
		} `yaml:"webhook"`
	} `yaml:"notifications"`
}

type AuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Type     string `yaml:"type"`
}

// LoadConfig loads configuration from YAML file
func LoadConfig(filename string) (Config, error) {
	var config Config
	
	// Check if file exists
	if !FileExists(filename) {
		return config, fmt.Errorf("config file %s does not exist", filename)
	}
	
	file, err := os.Open(filename)
	if err != nil {
		return config, err
	}
	defer file.Close()
	
	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}
	
	// Set default values if not specified
	if config.Scan.ConcurrentRequests == 0 {
		config.Scan.ConcurrentRequests = 10
	}
	if config.Scan.Timeout == 0 {
		config.Scan.Timeout = 30
	}
	if config.Scan.RateLimit == 0 {
		config.Scan.RateLimit = 5
	}
	if config.Safety.MaxScanDuration == 0 {
		config.Safety.MaxScanDuration = 3600 // 1 hour
	}
	
	return config, nil
}

// FileExists checks if a file exists
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// EnsureDir creates directory if it doesn't exist
func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// GetAbsolutePath returns absolute path
func GetAbsolutePath(path string) (string, error) {
	return filepath.Abs(path)
}

// GetHostname extracts hostname from URL
func GetHostname(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		// Fallback: extract hostname manually
		if strings.HasPrefix(urlStr, "http://") {
			urlStr = strings.TrimPrefix(urlStr, "http://")
		} else if strings.HasPrefix(urlStr, "https://") {
			urlStr = strings.TrimPrefix(urlStr, "https://")
		}
		
		if slashIndex := strings.Index(urlStr, "/"); slashIndex != -1 {
			urlStr = urlStr[:slashIndex]
		}
		
		return strings.ReplaceAll(urlStr, ".", "_")
	}
	
	hostname := parsed.Hostname()
	return strings.ReplaceAll(hostname, ".", "_")
}

// StringInSlice checks if string exists in slice
func StringInSlice(str string, list []string) bool {
	for _, item := range list {
		if item == str {
			return true
		}
	}
	return false
}

// ReadFileLines reads file and returns lines as slice
func ReadFileLines(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(content), "\n")
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			result = append(result, line)
		}
	}
	
	return result, nil
}

// IsBlacklisted checks if target is in blacklist
func IsBlacklisted(target string, blacklistedIPs []string) bool {
	if len(blacklistedIPs) == 0 {
		return false
	}
	
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	
	hostname := parsed.Hostname()
	for _, blacklistedIP := range blacklistedIPs {
		if strings.Contains(hostname, blacklistedIP) {
			return true
		}
	}
	
	return false
}

// IsWhitelisted checks if target is in whitelist
func IsWhitelisted(target string, whitelistedDomains []string) bool {
	if len(whitelistedDomains) == 0 {
		return true // No whitelist means all domains are allowed
	}
	
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	
	hostname := parsed.Hostname()
	for _, whitelistedDomain := range whitelistedDomains {
		if strings.Contains(hostname, whitelistedDomain) {
			return true
		}
	}
	
	return false
}

// WriteToFile writes data to file
func WriteToFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// CheckGitHubUpdates checks for updates on GitHub
func CheckGitHubUpdates(owner, repo, currentVersion string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, repo)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to check for updates: HTTP %d", resp.StatusCode)
	}
	
	var release struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return fmt.Errorf("failed to parse release information: %v", err)
	}
	
	// Remove 'v' prefix if present
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion = strings.TrimPrefix(currentVersion, "v")
	
	if latestVersion != currentVersion {
		color.New(color.FgYellow).Printf("Update available: %s -> %s\n", currentVersion, latestVersion)
		color.New(color.FgCyan).Printf("Download from: %s\n", release.HTMLURL)
	} else {
		color.New(color.FgGreen).Printf("You are using the latest version: %s\n", currentVersion)
	}
	
	return nil
}

// RemoveDuplicates removes duplicates from string slice
func RemoveDuplicates(slice []string) []string {
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

// ParseURL safely parses URL
func ParseURL(urlStr string) (*url.URL, error) {
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}
	return url.Parse(urlStr)
}
