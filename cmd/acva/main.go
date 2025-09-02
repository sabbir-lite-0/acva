package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/my-username/acva/core"
	"github.com/my-username/acva/core/gemini"
	"github.com/my-username/acva/utils"
	"github.com/urfave/cli/v2"
)

// ACVA Logo and version
const (
	Version = "1.0.0"
	Logo    = `
         _    ______     ___     
    / \  / ___\ \   / / \    
   / _ \| |    \ \ / / _ \   
  / ___ \ |___  \ V / ___ \  
 /_/   \_\____|  \_/_/   \_\ 
                             
Advanced Cybersecurity Vulnerability Assessment Tool v%s
`
)

func main() {
	// Add recovery from panics
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "Critical error: %v\n", r)
			os.Exit(1)
		}
	}()

	// Show logo and version
	fmt.Printf(Logo, Version)
	fmt.Println()

	app := &cli.App{
		Name:     "acva",
		Version:  Version,
		Usage:    "Advanced Cybersecurity Vulnerability Assessment Tool",
		Compiled: time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "ACVA Team",
				Email: "acva@example.com",
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "target",
				Aliases:  []string{"t"},
				Usage:    "Target URL to scan",
				Required: false,
			},
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Load configuration from `FILE`",
				Value:   "config.yaml",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output directory for reports",
				Value:   "reports",
			},
			&cli.StringFlag{
				Name:  "format",
				Usage: "Report format (html, json, markdown, pdf)",
				Value: "html",
			},
			&cli.StringSliceFlag{
				Name:    "module",
				Aliases: []string{"m"},
				Usage:   "Specify modules to run (crawler, analyzer, fuzzer, api, js, all)",
				Value:   cli.NewStringSlice("all"),
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Usage:   "Verbose output",
				Value:   false,
			},
			&cli.BoolFlag{
				Name:  "daemon",
				Usage: "Run in daemon mode",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "daemon-addr",
				Usage: "Daemon address",
				Value: "127.0.0.1:8080",
			},
			&cli.BoolFlag{
				Name:  "cluster",
				Usage: "Enable distributed scanning",
				Value: false,
			},
			&cli.StringFlag{
				Name:  "redis-addr",
				Usage: "Redis address for cluster mode",
				Value: "redis://127.0.0.1:6379",
			},
			&cli.BoolFlag{
				Name:  "update",
				Usage: "Check for updates from GitHub",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "no-banner",
				Usage: "Hide ACVA banner",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "validate-config",
				Usage: "Validate configuration file and exit",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "version",
				Usage: "Show version information",
				Value: false,
			},
			&cli.BoolFlag{
				Name:  "features",
				Usage: "Enable all advanced features including AI analysis",
				Value: false,
			},
		},
		Action: func(c *cli.Context) error {
			// Show version and exit
			if c.Bool("version") {
				fmt.Printf("ACVA version %s\n", Version)
				fmt.Printf("Go version: %s\n", runtime.Version())
				fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
				return nil
			}

			// Create context with cancellation
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			
			// Setup signal handling
			setupSignalHandling(cancel)

			// Check for updates
			if c.Bool("update") {
				if err := checkForUpdates(); err != nil {
					fmt.Printf("Update check failed: %v\n", err)
				}
			}

			if !c.Bool("no-banner") {
				fmt.Printf(Logo, Version)
				fmt.Println()
			}

			// Initialize logger with colored output
			logger := utils.NewLogger(c.Bool("verbose"))
			defer logger.Close()

			// Load configuration
			config, err := utils.LoadConfig(c.String("config"))
			if err != nil {
				logger.Error("Failed to load config: %v", err)
				return err
			}

			// Validate configuration
			if err := validateConfig(config); err != nil {
				logger.Error("Configuration validation failed: %v", err)
				return err
			}

			if c.Bool("validate-config") {
				logger.Success("Configuration validation passed")
				return nil
			}

			// Check if target is provided for scan mode
			if !c.Bool("daemon") && c.String("target") == "" {
				logger.Error("Target is required for scan mode")
				return fmt.Errorf("target is required")
			}

			// Create output directory
			outputDir := c.String("output")
			if err := utils.EnsureDir(outputDir); err != nil {
				logger.Error("Failed to create output directory: %v", err)
				return err
			}

			// Initialize HTTP client with rate limiting
			httpClient := utils.NewHTTPClient(config.Scan.Timeout)
			httpClient.SetRateLimit(config.Scan.RateLimit)

			// Initialize Gemini client if enabled in config or features flag
			var geminiClient *gemini.GeminiClient
			if config.Gemini.Enabled || c.Bool("features") {
				if len(config.Gemini.APIKeys) == 0 {
					logger.Warning("Gemini is enabled but no API keys configured")
				} else {
					geminiClient = gemini.NewGeminiClient(config.Gemini.APIKeys, config.Gemini.Model, logger)
					logger.Info("Gemini AI integration enabled with %d API keys", len(config.Gemini.APIKeys))
				}
			}

			// Initialize scanner with progress tracking and Gemini client
			scanner := core.NewScanner(logger, config, httpClient, geminiClient)

			// Set resource limits
			scanner.SetResourceLimits()

			// Start performance monitoring
			scanner.MonitorPerformance()

			// Check if running in daemon mode
			if c.Bool("daemon") {
				return runDaemonMode(c, logger, config, scanner)
			}

			// Run scan
			target := c.String("target")
			logger.Info("Starting scan for target: %s", target)

			// Check if target is blacklisted
			if utils.IsBlacklisted(target, config.Safety.BlacklistedIPs) {
				logger.Error("Target %s is blacklisted", target)
				return fmt.Errorf("target is blacklisted")
			}

			// Check if target is in whitelist (if whitelist is configured)
			if len(config.Safety.WhitelistedDomains) > 0 && 
			   !utils.IsWhitelisted(target, config.Safety.WhitelistedDomains) {
				logger.Error("Target %s is not in whitelist", target)
				return fmt.Errorf("target is not whitelisted")
			}

			// Determine which modules to run
			modules := c.StringSlice("module")
			runAll := false
			for _, module := range modules {
				if module == "all" {
					runAll = true
					break
				}
			}

			// Create progress tracker
			progress := utils.NewProgressTracker()
			defer progress.Stop()

			// Execute scan based on module selection with timeout
			scanCtx, scanCancel := context.WithTimeout(ctx, time.Duration(config.Safety.MaxScanDuration)*time.Second)
			defer scanCancel()

			var vulnerabilities []core.Vulnerability
			
			if runAll || utils.StringInSlice("crawler", modules) {
				progress.AddTask("Crawling target", 1)
				logger.Info("Running crawler module")
				vulns, err := scanner.CrawlAndAnalyze(scanCtx, target, progress)
				if err != nil {
					logger.Error("Crawler failed: %v", err)
				} else {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
				progress.CompleteTask("Crawling target")
			}

			if runAll || utils.StringInSlice("fuzzer", modules) {
				progress.AddTask("Fuzzing target", 1)
				logger.Info("Running fuzzer module")
				vulns, err := scanner.FuzzTarget(scanCtx, target, progress)
				if err != nil {
					logger.Error("Fuzzer failed: %v", err)
				} else {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
				progress.CompleteTask("Fuzzing target")
			}

			if runAll || utils.StringInSlice("api", modules) {
				progress.AddTask("Scanning APIs", 1)
				logger.Info("Running API scanner module")
				vulns, err := scanner.ScanAPIs(scanCtx, target, progress)
				if err != nil {
					logger.Error("API scanner failed: %v", err)
				} else {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
				progress.CompleteTask("Scanning APIs")
			}

			if runAll || utils.StringInSlice("js", modules) {
				progress.AddTask("Analyzing JavaScript", 1)
				logger.Info("Running JavaScript analyzer module")
				vulns, err := scanner.AnalyzeJavaScript(scanCtx, target, progress)
				if err != nil {
					logger.Error("JavaScript analyzer failed: %v", err)
				} else {
					vulnerabilities = append(vulnerabilities, vulns...)
				}
				progress.CompleteTask("Analyzing JavaScript")
			}

			// Check if scan was cancelled due to timeout
			select {
			case <-scanCtx.Done():
				if scanCtx.Err() == context.DeadlineExceeded {
					logger.Warning("Scan cancelled due to timeout")
				}
			default:
			}

			// Generate report
			progress.AddTask("Generating report", 1)
			logger.Info("Generating %s report with %d vulnerabilities", c.String("format"), len(vulnerabilities))
			reporter := core.NewReporter(logger)
			reportFile := filepath.Join(outputDir, fmt.Sprintf("acva_report_%s_%s.%s", 
				utils.GetHostname(target), 
				time.Now().Format("20060102_150405"), 
				c.String("format")))
			
			err = reporter.GenerateReport(vulnerabilities, reportFile, c.String("format"))
			if err != nil {
				logger.Error("Failed to generate report: %v", err)
				return err
			}
			progress.CompleteTask("Generating report")

			logger.Success("Scan completed. Report saved to: %s", reportFile)
			
			// Show summary
			showScanSummary(vulnerabilities, logger)
			
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runDaemonMode(c *cli.Context, logger *utils.Logger, config utils.Config, scanner *core.Scanner) error {
	daemonAddr := c.String("daemon-addr")
	logger.Info("Starting ACVA daemon on %s", daemonAddr)
	
	// Initialize dashboard
	dashboard := core.NewDashboard(logger)
	
	// Initialize API server
	apiServer := core.NewAPIServer(logger, config, scanner, dashboard)
	
	// Start server
	if err := apiServer.Start(daemonAddr); err != nil {
		logger.Error("Failed to start daemon: %v", err)
		return err
	}
	
	return nil
}

func checkForUpdates() error {
	// Implementation for GitHub version checking
	return utils.CheckGitHubUpdates("my-username", "acva", Version)
}

func showScanSummary(vulnerabilities []core.Vulnerability, logger *utils.Logger) {
	summary := make(map[string]int)
	types := make(map[string]int)
	
	for _, vuln := range vulnerabilities {
		summary[vuln.Severity]++
		types[vuln.Type]++
	}
	
	logger.Info("=== SCAN SUMMARY ===")
	logger.Info("High risk vulnerabilities: %d", summary["High"])
	logger.Info("Medium risk vulnerabilities: %d", summary["Medium"])
	logger.Info("Low risk vulnerabilities: %d", summary["Low"])
	logger.Info("Informational findings: %d", summary["Info"])
	logger.Info("Total vulnerabilities found: %d", len(vulnerabilities))
	
	if len(vulnerabilities) > 0 {
		logger.Warning("Vulnerabilities detected! Review the report for details.")
		logger.Info("Vulnerability types found:")
		for vulnType, count := range types {
			logger.Info("  - %s: %d", vulnType, count)
		}
	} else {
		logger.Success("No vulnerabilities found. Target appears secure.")
	}
}

func validateConfig(config utils.Config) error {
	if config.Scan.ConcurrentRequests <= 0 {
		return fmt.Errorf("concurrent_requests must be greater than 0")
	}
	if config.Scan.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}
	if config.Scan.RateLimit <= 0 {
		return fmt.Errorf("rate_limit must be greater than 0")
	}
	if config.Scan.MaxRetries < 0 {
		return fmt.Errorf("max_retries cannot be negative")
	}
	if config.Safety.MaxScanDuration <= 0 {
		return fmt.Errorf("max_scan_duration must be greater than 0")
	}
	return nil
}

func setupSignalHandling(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		fmt.Printf("\nReceived signal %s, shutting down gracefully...\n", sig)
		cancel()
		time.Sleep(1 * time.Second) // Give time for cleanup
		os.Exit(0)
	}()
}
