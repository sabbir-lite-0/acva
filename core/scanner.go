package core

import (
	"context"
	"fmt"
	"runtime"
	"syscall"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
)

type Scanner struct {
	logger       *utils.Logger
	config       utils.Config
	httpClient   *utils.HTTPClient
	crawler      *Crawler
	analyzer     *Analyzer
	fuzzer       *Fuzzer
	apiScanner   *APIScanner
	jsEngine     *JSEngine
	cluster      *ClusterManager
	stopChan     chan struct{}
	geminiClient *GeminiClient
}

func NewScanner(logger *utils.Logger, config utils.Config, httpClient *utils.HTTPClient, geminiClient *GeminiClient) *Scanner {
	return &Scanner{
		logger:       logger,
		config:       config,
		httpClient:   httpClient,
		crawler:      NewCrawler(logger, config, httpClient),
		analyzer:     NewAnalyzer(logger, config, httpClient, geminiClient),
		fuzzer:       NewFuzzer(logger, config, httpClient, geminiClient),
		apiScanner:   NewAPIScanner(logger, httpClient),
		jsEngine:     NewJSEngine(logger, config),
		stopChan:     make(chan struct{}),
		geminiClient: geminiClient,
	}
}

func (s *Scanner) CrawlAndAnalyze(ctx context.Context, target string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	startTime := time.Now()
	s.logger.Info("Starting crawl and analysis for: %s", target)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled")
	case <-s.stopChan:
		return nil, fmt.Errorf("scan stopped")
	default:
	}

	// Crawl target
	endpoints, err := s.crawler.Crawl(target)
	if err != nil {
		return nil, fmt.Errorf("crawling failed: %v", err)
	}

	s.logger.Info("Found %d endpoints, starting analysis", len(endpoints))

	// Analyze endpoints
	vulnerabilities, err := s.analyzer.Analyze(endpoints, progress)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %v", err)
	}

	elapsed := time.Since(startTime)
	s.logger.Success("Crawl and analysis completed in %s. Found %d vulnerabilities", elapsed, len(vulnerabilities))

	return vulnerabilities, nil
}

func (s *Scanner) FuzzTarget(ctx context.Context, target string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	startTime := time.Now()
	s.logger.Info("Starting fuzzing for: %s", target)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled")
	case <-s.stopChan:
		return nil, fmt.Errorf("scan stopped")
	default:
	}

	// First crawl to find endpoints
	endpoints, err := s.crawler.Crawl(target)
	if err != nil {
		return nil, fmt.Errorf("crawling failed: %v", err)
	}

	// Fuzz endpoints
	vulnerabilities, err := s.fuzzer.Fuzz(endpoints, progress)
	if err != nil {
		return nil, fmt.Errorf("fuzzing failed: %v", err)
	}

	elapsed := time.Since(startTime)
	s.logger.Success("Fuzzing completed in %s. Found %d vulnerabilities", elapsed, len(vulnerabilities))

	return vulnerabilities, nil
}

func (s *Scanner) ScanAPIs(ctx context.Context, target string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	startTime := time.Now()
	s.logger.Info("Starting API scanning for: %s", target)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled")
	case <-s.stopChan:
		return nil, fmt.Errorf("scan stopped")
	default:
	}

	// Discover API endpoints
	endpoints := s.apiScanner.DiscoverEndpoints(target)
	s.logger.Info("Discovered %d API endpoints", len(endpoints))

	// Test API endpoints
	var vulnerabilities []Vulnerability
	for _, endpoint := range endpoints {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return vulnerabilities, fmt.Errorf("scan cancelled")
		case <-s.stopChan:
			return vulnerabilities, fmt.Errorf("scan stopped")
		default:
		}

		s.logger.Debug("Testing API endpoint: %s", endpoint)
		vulns := s.apiScanner.TestAPIEndpoint(endpoint)
		vulnerabilities = append(vulnerabilities, vulns...)
		
		if progress != nil {
			progress.IncrementTask("Scanning APIs", 1)
		}
	}

	elapsed := time.Since(startTime)
	s.logger.Success("API scanning completed in %s. Found %d vulnerabilities", elapsed, len(vulnerabilities))

	return vulnerabilities, nil
}

func (s *Scanner) AnalyzeJavaScript(ctx context.Context, target string, progress *utils.ProgressTracker) ([]Vulnerability, error) {
	if !s.config.JavaScript.Enable {
		s.logger.Info("JavaScript analysis is disabled in config")
		return nil, nil
	}

	startTime := time.Now()
	s.logger.Info("Starting JavaScript analysis for: %s", target)

	// Check for context cancellation
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("scan cancelled")
	case <-s.stopChan:
		return nil, fmt.Errorf("scan stopped")
	default:
	}

	// Analyze JavaScript/SPA
	vulnerabilities, err := s.jsEngine.AnalyzeSPA(target)
	if err != nil {
		return nil, fmt.Errorf("JavaScript analysis failed: %v", err)
	}

	elapsed := time.Since(startTime)
	s.logger.Success("JavaScript analysis completed in %s. Found %d vulnerabilities", elapsed, len(vulnerabilities))

	return vulnerabilities, nil
}

func (s *Scanner) EnableClusterMode(redisAddr string) error {
	s.logger.Info("Enabling cluster mode with Redis: %s", redisAddr)
	
	clusterManager := NewClusterManager(redisAddr, s.logger, s.config)
	if clusterManager == nil {
		return fmt.Errorf("failed to initialize cluster manager")
	}
	
	s.cluster = clusterManager
	return nil
}

func (s *Scanner) DistributedScan(target string, scanConfig ScanConfig) (string, error) {
	if s.cluster == nil {
		return "", fmt.Errorf("cluster mode is not enabled")
	}
	
	return s.cluster.DistributeScan(target, scanConfig)
}

func (s *Scanner) SetResourceLimits() {
	// Set memory limit (80% of available memory)
	var memLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &memLimit); err == nil {
		memLimit.Cur = memLimit.Max * 80 / 100
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &memLimit); err == nil {
			s.logger.Info("Set memory limit to %dMB", memLimit.Cur/1024/1024)
		}
	}
}

func (s *Scanner) MonitorPerformance() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				s.logger.Debug("Memory usage: %vMB, Goroutines: %d", 
					m.Alloc/1024/1024, runtime.NumGoroutine())
			case <-s.stopChan:
				return
			}
		}
	}()
}

func (s *Scanner) Stop() {
	close(s.stopChan)
	s.logger.Info("Scanner stopped gracefully")
}

func (s *Scanner) HealthCheck() map[string]bool {
	health := make(map[string]bool)
	
	// Check HTTP client
	health["http_client"] = s.httpClient != nil
	
	// Check modules
	health["crawler"] = s.crawler != nil
	health["analyzer"] = s.analyzer != nil
	health["fuzzer"] = s.fuzzer != nil
	health["api_scanner"] = s.apiScanner != nil
	health["js_engine"] = s.jsEngine != nil
	
	// Check cluster if enabled
	if s.cluster != nil {
		health["cluster"] = true
	} else {
		health["cluster"] = false
	}
	
	return health
}

// ScanConfig represents scan configuration for distributed scanning
type ScanConfig struct {
	Target    string   `json:"target"`
	Modules   []string `json:"modules"`
	Depth     int      `json:"depth"`
	Timeout   int      `json:"timeout"`
	ScanID    string   `json:"scan_id"`
	StartedAt string   `json:"started_at"`
}
