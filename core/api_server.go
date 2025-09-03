package core

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type APIServer struct {
	scanner   *Scanner
	reporter  *Reporter
	cluster   *ClusterManager
	dashboard *Dashboard
	mu        sync.Mutex
}

func NewAPIServer(scanner *Scanner, reporter *Reporter, cluster *ClusterManager, dashboard *Dashboard) *APIServer {
	return &APIServer{
		scanner:   scanner,
		reporter:  reporter,
		cluster:   cluster,
		dashboard: dashboard,
	}
}

func (s *APIServer) RegisterRoutes(r *mux.Router) {
	// Scan routes
	r.HandleFunc("/api/scan/status/{id}", s.getScanStatus).Methods("GET")
	r.HandleFunc("/api/scan/stop/{id}", s.stopScan).Methods("POST")
	r.HandleFunc("/api/scans", s.listScans).Methods("GET")

	// Dashboard routes
	r.HandleFunc("/api/dashboard/ws", s.handleDashboardWebSocket)
	r.HandleFunc("/api/dashboard/stats", s.getDashboardStats).Methods("GET")

	// Report routes
	r.HandleFunc("/api/reports", s.listReports).Methods("GET")
	r.HandleFunc("/api/report/{id}", s.getReport).Methods("GET")
	r.HandleFunc("/api/report/{id}", s.deleteReport).Methods("DELETE")

	// Cluster routes
	r.HandleFunc("/api/cluster/nodes", s.getClusterNodes).Methods("GET")
	r.HandleFunc("/api/cluster/nodes/{id}", s.getClusterNode).Methods("GET")
	r.HandleFunc("/api/cluster/stats", s.getClusterStats).Methods("GET")

	// Scan trigger
	r.HandleFunc("/api/scan", s.startScan).Methods("POST")
}

func (s *APIServer) startScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
		Mode   string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	id := time.Now().Format("20060102150405")

	// Broadcast scan start
	s.dashboard.BroadcastUpdate(DashboardMessage{
		Type: "scan_started",
		Data: map[string]interface{}{"id": id, "target": req.Target},
	})

	go func() {
		var vulnerabilities []Vulnerability
		var stages []string

		add := func(vs []Vulnerability, err error, stage string) {
			if err != nil {
				log.Printf("Stage %s failed: %v", stage, err)
				return
			}
			vulnerabilities = append(vulnerabilities, vs...)
			stages = append(stages, stage)
			s.dashboard.BroadcastUpdate(DashboardMessage{
				Type: "stage_completed",
				Data: map[string]interface{}{"id": id, "stage": stage},
			})
		}

		switch req.Mode {
		case "crawl":
			vs, err := s.scanner.CrawlAndAnalyze(r.Context(), req.Target, nil)
			add(vs, err, "crawl+analyze")
		case "fuzz":
			vs, err := s.scanner.FuzzTarget(r.Context(), req.Target, nil)
			add(vs, err, "fuzz")
		case "api":
			vs, err := s.scanner.ScanAPIs(r.Context(), req.Target, nil)
			add(vs, err, "api_scan")
		case "js":
			vs, err := s.scanner.AnalyzeJavaScript(r.Context(), req.Target, nil)
			add(vs, err, "js_analysis")
		default:
			vs, err := s.scanner.CrawlAndAnalyze(r.Context(), req.Target, nil)
			add(vs, err, "crawl+analyze")
			vs, err = s.scanner.FuzzTarget(r.Context(), req.Target, nil)
			add(vs, err, "fuzz")
			vs, err = s.scanner.ScanAPIs(r.Context(), req.Target, nil)
			add(vs, err, "api_scan")
			vs, err = s.scanner.AnalyzeJavaScript(r.Context(), req.Target, nil)
			add(vs, err, "js_analysis")
		}

		report := Report{
			ID:              id,
			Target:          req.Target,
			Vulnerabilities: vulnerabilities,
			GeneratedAt:     time.Now(),
		}
		s.reporter.SaveReport(report)

		s.dashboard.BroadcastUpdate(DashboardMessage{
			Type: "scan_completed",
			Data: map[string]interface{}{"id": id, "stages": stages},
		})
	}()

	s.respondWithJSON(w, http.StatusAccepted, map[string]string{"id": id})
}

// --- Scan handlers ---
func (s *APIServer) getScanStatus(w http.ResponseWriter, r *http.Request) {
	s.respondWithError(w, http.StatusNotImplemented, "getScanStatus not implemented")
}

func (s *APIServer) stopScan(w http.ResponseWriter, r *http.Request) {
	s.respondWithError(w, http.StatusNotImplemented, "stopScan not implemented")
}

func (s *APIServer) listScans(w http.ResponseWriter, r *http.Request) {
	s.respondWithJSON(w, http.StatusOK, []string{})
}

// --- Dashboard handlers ---
func (s *APIServer) handleDashboardWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	s.dashboard.AddClient(conn)
}

func (s *APIServer) getDashboardStats(w http.ResponseWriter, r *http.Request) {
	stats := s.dashboard.GetStats()
	s.respondWithJSON(w, http.StatusOK, stats)
}

// --- Report handlers ---
func (s *APIServer) listReports(w http.ResponseWriter, r *http.Request) {
	reports := s.reporter.ListReports()
	s.respondWithJSON(w, http.StatusOK, reports)
}

func (s *APIServer) getReport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	report, err := s.reporter.LoadReport(id)
	if err != nil {
		s.respondWithError(w, http.StatusNotFound, "Report not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, report)
}

func (s *APIServer) deleteReport(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.reporter.DeleteReport(id); err != nil {
		s.respondWithError(w, http.StatusInternalServerError, "Failed to delete report")
		return
	}
	s.respondWithJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// --- Cluster handlers ---
func (s *APIServer) getClusterNodes(w http.ResponseWriter, r *http.Request) {
	nodes := s.cluster.ListNodes()
	s.respondWithJSON(w, http.StatusOK, nodes)
}

func (s *APIServer) getClusterNode(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	node, err := s.cluster.GetNode(id)
	if err != nil {
		s.respondWithError(w, http.StatusNotFound, "Node not found")
		return
	}
	s.respondWithJSON(w, http.StatusOK, node)
}

func (s *APIServer) getClusterStats(w http.ResponseWriter, r *http.Request) {
	stats := s.cluster.GetStats()
	s.respondWithJSON(w, http.StatusOK, stats)
}

// --- Helpers ---
func (s *APIServer) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func (s *APIServer) respondWithError(w http.ResponseWriter, code int, message string) {
	s.respondWithJSON(w, code, map[string]string{"error": message})
}
