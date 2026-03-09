package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DashboardServer serves a live dashboard over HTTP with SSE updates.
type DashboardServer struct {
	analyzer *Analyzer
	server   *http.Server
	port     int
}

// DashboardSnapshot is the JSON payload sent to the browser each tick.
type DashboardSnapshot struct {
	Timestamp   string              `json:"timestamp"`
	Uptime      string              `json:"uptime"`
	Stopped     bool                `json:"stopped"`
	Packets     int64               `json:"packets"`
	Bytes       int64               `json:"bytes"`
	Flows       int                 `json:"flows"`
	Threats     int                 `json:"threats"`
	HTTPReqs    int                 `json:"httpReqs"`
	C2Count     int                 `json:"c2Count"`
	Credentials int                 `json:"credentials"`
	ThreatScore float64             `json:"threatScore"`
	Protocols   map[string]int64    `json:"protocols"`
	TopTalkers  []TalkerInfo        `json:"topTalkers"`
	RecentThreats []Threat          `json:"recentThreats"`
	RecentC2    []C2Detection       `json:"recentC2"`
	TopFlows    []FlowSnapshot      `json:"topFlows"`
}

// FlowSnapshot is a serializable subset of Flow for the dashboard.
type FlowSnapshot struct {
	SrcIP   string `json:"srcIP"`
	SrcPort uint16 `json:"srcPort"`
	DstIP   string `json:"dstIP"`
	DstPort uint16 `json:"dstPort"`
	Proto   string `json:"proto"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

// NewDashboardServer creates a dashboard bound to the given analyzer.
func NewDashboardServer(a *Analyzer, port int) *DashboardServer {
	return &DashboardServer{
		analyzer: a,
		port:     port,
	}
}

// Start begins serving the dashboard. Non-blocking.
func (ds *DashboardServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ds.handleDashboard)
	mux.HandleFunc("/api/stream", ds.handleSSE)
	mux.HandleFunc("/api/snapshot", ds.handleSnapshot)

	ds.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ds.port),
		Handler: mux,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := ds.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Give the server a moment to fail on bind errors.
	select {
	case err := <-errCh:
		return fmt.Errorf("dashboard server failed to start: %w", err)
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

// Shutdown gracefully stops the dashboard server.
func (ds *DashboardServer) Shutdown() {
	if ds.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		ds.server.Shutdown(ctx)
	}
}

// handleDashboard serves the embedded HTML page.
func (ds *DashboardServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(dashboardTemplate))
}

// handleSnapshot returns a single JSON snapshot.
func (ds *DashboardServer) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	snap := ds.buildSnapshot()
	json.NewEncoder(w).Encode(snap)
}

// handleSSE streams JSON snapshots at ~1Hz via Server-Sent Events.
func (ds *DashboardServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := ds.buildSnapshot()
			data, _ := json.Marshal(snap)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()

			// If capture has ended, send one final event and close.
			if snap.Stopped {
				fmt.Fprintf(w, "event: done\ndata: capture ended\n\n")
				flusher.Flush()
				return
			}
		}
	}
}

// buildSnapshot assembles a DashboardSnapshot from the analyzer's live state.
func (ds *DashboardServer) buildSnapshot() DashboardSnapshot {
	a := ds.analyzer

	topFlowsRaw := a.GetTopFlows(10)
	topFlows := make([]FlowSnapshot, len(topFlowsRaw))
	for i, f := range topFlowsRaw {
		topFlows[i] = FlowSnapshot{
			SrcIP:   f.Key.SrcIP,
			SrcPort: f.Key.SrcPort,
			DstIP:   f.Key.DstIP,
			DstPort: f.Key.DstPort,
			Proto:   f.Key.Proto,
			Packets: f.Packets,
			Bytes:   f.Bytes,
		}
	}

	return DashboardSnapshot{
		Timestamp:     time.Now().Format(time.RFC3339),
		Uptime:        time.Since(a.GetStartTime()).Truncate(time.Second).String(),
		Stopped:       a.IsCaptureStopped(),
		Packets:       a.GetProcessed(),
		Bytes:         a.GetTotalBytes(),
		Flows:         a.GetFlowCount(),
		Threats:       a.GetThreatCount(),
		HTTPReqs:      a.GetHTTPRequestCount(),
		C2Count:       a.GetC2DetectionCount(),
		Credentials:   a.GetCredentialCount(),
		ThreatScore:   ds.liveThreatScore(),
		Protocols:     a.GetProtocolDistribution(),
		TopTalkers:    a.GetTopTalkers(10),
		RecentThreats: a.GetRecentThreats(20),
		RecentC2:      a.GetRecentC2(10),
		TopFlows:      topFlows,
	}
}

// liveThreatScore computes a lightweight threat score from current state.
func (ds *DashboardServer) liveThreatScore() float64 {
	threats := ds.analyzer.GetThreats()
	if len(threats) == 0 {
		return 0
	}
	high, med, low := 0, 0, 0
	for _, t := range threats {
		switch t.Severity {
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		}
	}
	score := float64(high)*5.0 + float64(med)*2.0 + float64(low)*0.5
	if score > 100 {
		score = 100
	}
	return score
}
