package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
	"github.com/gorilla/mux"
)

type APIServer struct {
	logger    *utils.Logger
	config    utils.Config
	scanner   *Scanner
	dashboard *Dashboard
	router    *mux.Router
}

func NewAPIServer(logger *utils.Logger, config utils.Config, scanner *Scanner, dashboard *Dashboard) *APIServer {
	server := &APIServer{
		logger:    logger,
		config:    config,
		scanner:   scanner,
		dashboard: dashboard,
		router:    mux.NewRouter(),
	}
	
	server.setupRoutes()
	return server
}

func (s *APIServer) setupRoutes() {
	// API routes
	api := s.router.PathPrefix("/api/v1").Subrouter()
	
	// Scan endpoints
	api.HandleFunc("/scan", s.startScan).Methods("POST")
	api.HandleFunc("/scan/{id}", s.getScanStatus).Methods("GET")
	api.HandleFunc("/scan/{id}", s.stopScan).Methods("DELETE")
	api.HandleFunc("/scans", s.listScans).Methods("GET")
	
	// Dashboard endpoints
	api.HandleFunc("/dashboard/ws", s.handleDashboardWebSocket)
	api.HandleFunc("/dashboard/stats", s.getDashboardStats).Methods("GET")
	
	// Report endpoints
	api.HandleFunc("/reports", s.listReports).Methods("GET")
	api.HandleFunc("/reports/{id}", s.getReport).Methods("GET")
	api.HandleFunc("/reports/{id}", s.deleteReport).Methods("DELETE")
	
	// Cluster endpoints
	api.HandleFunc("/cluster/nodes", s.getClusterNodes).Methods("GET")
	api.HandleFunc("/cluster/nodes/{id}", s.getClusterNode).Methods("GET")
	api.HandleFunc("/cluster/stats", s.getClusterStats).Methods("GET")
	
	// Serve static files for dashboard
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
}

func (s *APIServer) Start(addr string) error {
	s.logger.Info("Starting API server on %s", addr)
	return http.ListenAndServe(addr, s.router)
}

func (s *APIServer) startScan(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Target  string   `json:"target"`
		Modules []string `json:"modules"`
		Depth   int      `json:"depth"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	
	if request.Target == "" {
		s.respondWithError(w, http.StatusBadRequest, "Target is required")
		return
	}
	
	// Start scan in background
	go func() {
		scanID := generateUUID()
		s.logger.Info("Starting scan %s for target: %s", scanID, request.Target)
		
		// Update dashboard
		s.dashboard.BroadcastUpdate(DashboardMessage{
			Type: "scan_started",
			Payload: map[string]interface{}{
				"id":     scanID,
				"target": request.Target,
				"time":   time.Now(),
			},
		})
		
		// Run scan based on requested modules
		var vulnerabilities []Vulnerability
		
		if len(request.Modules) == 0 || utils.StringInSlice("all", request.Modules) {
			vulns, err := s.scanner.CrawlAndAnalyze(r.Context(), request.Target, nil)
			if err != nil {
				s.logger.Error("Crawl and analyze failed: %v", err)
			} else {
				vulnerabilities = append(vulnerabilities, vulns...)
			}
		} else {
			// Run specific modules
			for _, module := range request.Modules {
				switch module {
				case "crawler":
					vulns, err := s.scanner.CrawlAndAnalyze(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("Crawler module failed: %v", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns...)
					}
				case "fuzzer":
					vulns, err := s.scanner.FuzzTarget(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("Fuzzer module failed: %v", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns...)
					}
				case "api":
					vulns, err := s.scanner.ScanAPIs(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("API scanner module failed: %v极", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns...)
					}
				case "js":
					vulns, err := s.scanner.AnalyzeJavaScript(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("JavaScript analyzer module failed: %v", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns...)
					}
				}
			}
		}
		
		// Generate report
		reporter := NewReporter(s.logger)
		reportFile := fmt.Sprintf("reports/acva_report_%s_%s.json",
			utils.GetHostname(request.Target),
			time.Now().Format("20060102_150405"))
		
		if err := reporter.GenerateReport(vulnerabilities, reportFile, "json"); err != nil {
			s.logger.Error("Failed to generate report: %v", err)
		}
		
		// Update dashboard
		s.dashboard.BroadcastUpdate(DashboardMessage{
			Type: "scan_completed",
			Payload: map[string]interface{}{
				"id":              scanID,
				"target":          request.Target,
				"vulnerabilities": len(vulnerabilities),
				"report":          reportFile,
				"time":            time.Now(),
			},
		})
	}()
	
	s.respondWithJSON(w, http.StatusAccepted, map[string]string{
		"message": "Scan started successfully",
		"status":  "accepted",
	})
}

func (s *APIServer) getScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]
	
	// In a real implementation, this would fetch from a database
	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"id":     scanID,
		"status": "running",
		"progress": 65,
	})
}

func (s *APIServer) stopScan(w http.ResponseWriter, r *http.Request) {
	vars := m极.Vars(r)
	scanID := vars["id"]
	
	// In a real implementation, this would stop the scan
	s.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Scan %s stopped", scanID),
	})
}

func (s *APIServer) listScans(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, this would list all scans from a database
	scans := []map[string]interface{}{
		{
			"id":     "scan-1",
			"target": "https://example.com",
			"status": "completed",
			"start":  time.Now().Add(-1 * time.Hour),
			"end":    time.Now().Add(-30 * time.Minute),
		},
		{
			"极":     "scan-2",
			"target": "https://test.com",
			"status": "running",
			"start":  time.Now().Add(-10 * time.Minute),
			"end":    nil,
		},
	}
	
	s.respondWithJSON(w, http.StatusOK, scans)
}

func (s *APIServer) handleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	s.dashboard.HandleConnections(w, r)
}

func (s *APIServer) getDashboardStats(w http极.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_scans":      42,
		"active_scans":     3,
		"vulnerabilities":  156,
		"high_risk":        23,
		"medium_risk":      45,
		"low_risk":         88,
		"cluster_nodes":    5,
		"uptime":           "36h 12m",
		"last_scan":        time.Now().Add(-10 * time.Minute),
	}
	
	s.respondWithJSON(w, http.StatusOK, stats)
}

func (s *APIServer) listReports(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, this would list reports from the filesystem
	reports := []map[string]interface{}{
		{
			"id":        "report-1",
			"target":    "https://example.com",
			"date":      time.Now().Add(-1 * time.Hour),
			"format":    "json",
			"vulnerabilities": 12,
			"path":      "reports/example_com_report.json",
		},
		{
			"id":        "report-2",
			"target":    "https://test.com",
			"date":      time.Now().Add(-2 * time.Hour),
			"format":    "html",
			"vulnerabilities": 8,
			"path":      "reports/test_com_report.html",
		},
	}
	
	s.respondWithJSON(w, http.StatusOK, reports)
}

func (s *APIServer) getReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	reportID := vars["id"]
	
	// In a real implementation, this would load the report from filesystem
	report := map[string]interface{}{
		"id":        reportID,
		"target":    "https://example.com",
		"date":      time.Now().Add(-1 * time.Hour),
		"format":    "json",
		"vulnerabilities": []Vulnerability{},
	}
	
	s.respondWithJSON(w, http.StatusOK, report)
}

func (s *APIServer) deleteReport(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	reportID := vars["id"]
	
	// In a real implementation, this would delete the report file
	s.respondWithJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Report %s deleted", reportID),
	})
}

func (s *APIServer) getClusterNodes(w http.ResponseWriter, r *http.Request) {
	// In a real implementation, this would get cluster nodes from cluster manager
	nodes := []map[string]interface{}{
		{
			"id":        "node-1",
			"address":   "192.168.1.101:8080",
			"status":    "active",
			"workload":  35,
			"last_seen": time.Now(),
		},
		{
			"id":        "node-2",
			"address":   "192.168.1.102:8080",
			"status":    "active",
			"workload":  20,
			"last_seen": time.Now(),
		},
		{
			"id":        "node-3",
			"address":   "192.168.1.103:8080",
			"status":    "offline",
			"workload":  0,
			"last_seen": time.Now().Add(-5 * time.Minute),
		},
	}
	
	s.respondWithJSON(w, http.StatusOK, nodes)
}

func (s *APIServer) getClusterNode(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["id"]
	
	// In a real implementation, this would get node details from cluster manager
	node := map[string]interface{}{
		"id":        nodeID,
		"address":   "192.168.1.101:8080",
		"status":    "active",
		"workload":  35,
		"cpu":       45.2,
		"memory":    62.8,
		"network":   12.4,
		"last_seen": time.Now(),
	}
	
	s.respondWithJSON(w, http.StatusOK, node)
}

func (s *APIServer极) getClusterStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string极]interface{}{
		"total_nodes":   5,
		"active_nodes":  4,
		"idle_nodes":    2,
		"busy_nodes":    2,
		"offline_nodes": 1,
		"total_workload": 65,
		"avg_cpu":       42.3,
		"avg_memory":    58.7,
		"total_scans":   24,
	}
	
	s.respondWithJSON(w, http.StatusOK, stats)
}

func (s *APIServer) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func (s *APIServer) respondWithError(w http.ResponseWriter, code int, message string) {
	s.respondWithJSON(w, code, map[string]string{"error": message})
}

// Helper function to generate UUID
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
