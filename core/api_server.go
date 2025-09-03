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
				vulnerabilities = append(vulnerabilities, vulns)
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
						vulnerabilities = append(vulnerabilities, vulns)
					}
				case "fuzzer":
					vulns, err := s.scanner.FuzzTarget(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("Fuzzer module failed: %v", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns)
					}
				case "api":
					vulns, err := s.scanner.ScanAPIs(r.Context(), request.Target, nil)
					if err != nil {
						s.logger.Error("API scan failed: %v", err)
					} else {
						vulnerabilities = append(vulnerabilities, vulns)
					}
				default:
					s.logger.Warn("Unknown module: %s", module)
				}
			}
		}

		// Save scan results (simplified for now)
		s.logger.Info("Scan %s completed. Found %d vulnerabilities.", scanID, len(vulnerabilities))
	}()
	
	s.respondWithJSON(w, http.StatusAccepted, map[string]string{
		"status": "scan started",
	})
}

// Placeholder response helpers

func (s *APIServer) respondWithError(w http.ResponseWriter, code int, message string) {
	s.respondWithJSON(w, code, map[string]string{"error": message})
}

func (s *APIServer) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
