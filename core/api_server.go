// SPDX-License-Identifier: MIT
package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sabbir-lite-0/acva/utils"
)

// --- In-memory state (minimal viable implementation) ---

type scanStatus struct {
	ID         string           `json:"id"`
	Target     string           `json:"target"`
	Modules    []string         `json:"modules,omitempty"`
	Status     string           `json:"status"` // queued, running, completed, error, stopped
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at,omitempty"`
	Error      string           `json:"error,omitempty"`
	Results    []Vulnerability  `json:"results,omitempty"`
}

type APIServer struct {
	logger      *utils.Logger
	config      utils.Config
	scanner     *Scanner
	dashboard   *Dashboard
	router      *mux.Router

	// local state
	scans       map[string]*scanStatus
	reports     map[string][]Vulnerability
}

func NewAPIServer(logger *utils.Logger, config utils.Config, scanner *Scanner, dashboard *Dashboard) *APIServer {
	s := &APIServer{
		logger:    logger,
		config:    config,
		scanner:   scanner,
		dashboard: dashboard,
		router:    mux.NewRouter(),
		scans:     map[string]*scanStatus{},
		reports:   map[string][]Vulnerability{},
	}
	s.setupRoutes()
	return s
}

func (s *APIServer) Router() *mux.Router {
	return s.router
}

func (s *APIServer) Start(addr string) error {
	s.logger.Info("Starting API server on %s", addr)
	return http.ListenAndServe(addr, s.router)
}

func (s *APIServer) setupRoutes() {
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

	// Cluster endpoints (best-effort)
	api.HandleFunc("/cluster/nodes", s.getClusterNodes).Methods("GET")
	api.HandleFunc("/cluster/nodes/{id}", s.getClusterNode).Methods("GET")
	api.HandleFunc("/cluster/stats", s.getClusterStats).Methods("GET")

	// Serve static (optional)
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static/")))
}

// ---- Handlers ----

// startScan kicks off a scan using the Scanner. It stores status in-memory.
func (s *APIServer) startScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target  string   `json:"target"`
		Modules []string `json:"modules"` // e.g., ["crawler","fuzzer","api","js"]
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Target == "" {
		s.respondWithError(w, http.StatusBadRequest, "target is required")
		return
	}

	id := s.generateID()
	entry := &scanStatus{
		ID:        id,
		Target:    req.Target,
		Modules:   req.Modules,
		Status:    "queued",
		StartedAt: time.Now(),
	}
	s.scans[id] = entry

	// notify dashboard
	if s.dashboard != nil {
		s.dashboard.BroadcastUpdate(DashboardMessage{
			Type: "scan_started",
			Message: "scan queued",
			Data: map[string]interface{}{"id": id, "target": req.Target},
			Timestamp: time.Now(),
		})
	}

	go func() {
		entry.Status = "running"
		var vulns []Vulnerability

		runAll := len(req.Modules) == 0
		add := func(vs []Vulnerability, err error, stage string) {
			if err != nil {
				s.logger.Error("%s failed: %v", stage, err)
				return
			}
			vulns = append(vulns, vs...)
		}

		if runAll || contains(req.Modules, "crawler") {
			add(s.scanner.CrawlAndAnalyze(r.Context(), req.Target, nil), "crawl+analyze")
		}
		if runAll || contains(req.Modules, "fuzzer") {
			add(s.scanner.FuzzTarget(r.Context(), req.Target, nil), "fuzzer")
		}
		if runAll || contains(req.Modules, "api") {
			add(s.scanner.ScanAPIs(r.Context(), req.Target, nil), "api-scan")
		}
		if runAll || contains(req.Modules, "js") {
			add(s.scanner.AnalyzeJavaScript(r.Context(), req.Target, nil), "js-analyze")
		}

		entry.Results = vulns
		entry.Status = "completed"
		now := time.Now()
		entry.FinishedAt = &now

		// store a "report" for the ID (best-effort)
		s.reports[id] = vulns

		if s.dashboard != nil {
			s.dashboard.BroadcastUpdate(DashboardMessage{
				Type: "scan_completed",
				Message: "scan finished",
				Data: map[string]interface{}{"id": id, "vulnerabilities": len(vulns)},
				Timestamp: time.Now(),
			})
		}
	}()

	s.respondWithJSON(w, http.StatusAccepted, map[string]string{"id": id, "status": "queued"})
}

func contains(arr []string, v string) bool {
	for _, s := range arr {
		if s == v {
			return true
		}
	}
	return false
}

func (s *APIServer) getScanStatus(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		s.respondWithError(w, http.StatusBadRequest, "missing id")
		return
	}
	entry, ok := s.scans[id]
	if !ok {
		s.respondWithError(w, http.StatusNotFound, "scan not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, entry)
}

func (s *APIServer) stopScan(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	entry, ok := s.scans[id]
	if !ok {
		s.respondWithError(w, http.StatusNotFound, "scan not found")
		return
	}
	// best-effort: we don't have a cancelable context in this skeleton,
	// mark as stopped.
	entry.Status = "stopped"
	now := time.Now()
	entry.FinishedAt = &now

	if s.dashboard != nil {
		s.dashboard.BroadcastUpdate(DashboardMessage{
			Type: "scan_stopped",
			Message: "scan stopped by user",
			Data: map[string]interface{}{"id": id},
			Timestamp: time.Now(),
		})
	}

	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *APIServer) listScans(w http.ResponseWriter, r *http.Request) {
	out := make([]*scanStatus, 0, len(s.scans))
	for _, v := range s.scans {
		out = append(out, v)
	}
	s.respondWithJSON(w, http.StatusOK, out)
}

// WebSocket: delegate to dashboard if available, else provide a basic echo of stats
func (s *APIServer) handleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	if s.dashboard != nil {
		// dashboard has its own upgrader/handler
		s.dashboard.HandleWebSocket(w, r)
		return
	}
	// Fallback minimal websocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "upgrade failed", http.StatusBadRequest)
		return
	}
	defer conn.Close()
	for {
		stats := map[string]interface{}{
			"connected_clients": 1,
			"timestamp":         time.Now().Format(time.RFC3339),
		}
		_ = conn.WriteJSON(stats)
		time.Sleep(3 * time.Second)
	}
}

func (s *APIServer) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	if s.dashboard != nil {
		s.respondWithJSON(w, http.StatusOK, s.dashboard.GetStats())
		return
	}
	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"connected_clients": 0,
		"timestamp":         time.Now().Format(time.RFC3339),
	})
}

func (s *APIServer) listReports(w http.ResponseWriter, r *http.Request) {
	list := make([]map[string]interface{}, 0, len(s.reports))
	for id, vulns := range s.reports {
		list = append(list, map[string]interface{}{
			"id":               id,
			"vulnerability_count": len(vulns),
		})
	}
	s.respondWithJSON(w, http.StatusOK, list)
}

func (s *APIServer) getReport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	v, ok := s.reports[id]
	if !ok {
		s.respondWithError(w, http.StatusNotFound, "report not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"id":            id,
		"vulnerabilities": v,
	})
}

func (s *APIServer) deleteReport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, ok := s.reports[id]; !ok {
		s.respondWithError(w, http.StatusNotFound, "report not found")
		return
	}
	delete(s.reports, id)
	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *APIServer) getClusterNodes(w http.ResponseWriter, r *http.Request) {
	// No direct cluster exposure in placeholders; return empty list
	s.respondWithJSON(w, http.StatusOK, []map[string]string{})
}

func (s *APIServer) getClusterNode(w http.ResponseWriter, r *http.Request) {
	// No direct cluster state; return 404
	s.respondWithError(w, http.StatusNotFound, "node not found")
}

func (s *APIServer) getClusterStats(w http.ResponseWriter, r *http.Request) {
	// Provide scanner health as "cluster" stats
	stats := s.scanner.HealthCheck()
	s.respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"health": stats,
		"time":   time.Now().Format(time.RFC3339),
	})
}

// ---- helpers ----

func (s *APIServer) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	resp, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (s *APIServer) respondWithError(w http.ResponseWriter, code int, message string) {
	s.respondWithJSON(w, code, map[string]string{"error": message})
}

func (s *APIServer) generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
