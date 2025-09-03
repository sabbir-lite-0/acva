package core

import "time"

// Vulnerability represents a security vulnerability found during scanning
type Vulnerability struct {
	Type        string   `json:"type"`
	URL         string   `json:"url"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Payload     string   `json:"payload,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// ScanConfig represents the configuration for a scan
type ScanConfig struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Modules   []string  `json:"modules"`
	Depth     int       `json:"depth"`
	Timeout   int       `json:"timeout"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
	Progress  int       `json:"progress"`
}

// WorkerNode represents a worker node in the cluster
type WorkerNode struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	Workload  int       `json:"workload"`
	CPUUsage  float64  `json:"cpu_usage"`
	MemUsage  float64  `json:"mem_usage"`
}

// ClusterStats represents statistics about the cluster
type ClusterStats struct {
	TotalNodes    int     `json:"total_nodes"`
	ActiveNodes   int     `json:"active_nodes"`
	IdleNodes     int     `json:"idle_nodes"`
	OfflineNodes  int     `json:"offline_nodes"`
	TotalWorkload int     `json:"total_workload"`
	AvgCPUUsage   float64 `json:"avg_cpu_usage"`
	AvgMemUsage   float64 `json:"avg_mem_usage"`
}

// APIRequest represents an API request
type APIRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// APIResponse represents an API response
type APIResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Latency time.Duration     `json:"latency"`
}

// ReportOptions represents options for report generation
type ReportOptions struct {
	Format      string `json:"format"`
	OutputDir   string `json:"output_dir"`
	IncludeReq  bool   `json:"include_requests"`
	IncludeResp bool   `json:"include_responses"`
	Detailed    bool   `json:"detailed"`
}

// Notification represents a notification
type Notification struct {
	Type      string                 `json:"type"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	RequestsPerSecond int           `json:"requests_per_second"`
	Burst             int           `json:"burst"`
	Enabled           bool          `json:"enabled"`
	Scope             string        `json:"scope"`
	Penalty           time.Duration `json:"penalty"`
}
