package analyzer

import (
	"fmt"
	"time"
)

// DataExfiltration represents detected data exfiltration
type DataExfiltration struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	DstPort     uint16
	Protocol    string
	BytesOut    int64
	Duration    time.Duration
	Rate        float64
	Method      string
	Confidence  string
}

func (a *Analyzer) detectExfiltration() []DataExfiltration {
	fmt.Println("Detecting data exfiltration...")
	
	exfils := []DataExfiltration{}
	
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	for key, flow := range a.flows {
		duration := flow.EndTime.Sub(flow.StartTime)
		if duration.Seconds() < 1 {
			continue
		}
		
		// Calculate upload rate (bytes per second)
		uploadRate := float64(flow.Bytes) / duration.Seconds()
		
		// Detect large uploads (>50KB/s sustained)
		if uploadRate > 50000 {
			method := ""
			confidence := "medium"
			
			switch {
			case key.DstPort == 80:
				method = "HTTP POST exfiltration"
				confidence = "high"
			case key.DstPort == 443:
				method = "HTTPS exfiltration"
				confidence = "high"
			case key.DstPort == 21:
				method = "FTP upload exfiltration"
				confidence = "high"
			case key.DstPort == 22:
				method = "SSH/SCP exfiltration"
				confidence = "high"
			case key.DstPort == 53:
				method = "DNS tunneling exfiltration"
				confidence = "high"
			case key.DstPort == 25 || key.DstPort == 587:
				method = "SMTP email exfiltration"
				confidence = "high"
			case key.DstPort == 445:
				method = "SMB file transfer exfiltration"
				confidence = "medium"
			default:
				method = "Unknown protocol exfiltration"
				confidence = "low"
			}
			
			// Higher confidence for very large transfers
			if flow.Bytes > 10*1024*1024 { // >10MB
				if confidence == "medium" {
					confidence = "high"
				}
			}
			
			exfils = append(exfils, DataExfiltration{
				Timestamp:  flow.StartTime,
				SrcIP:      key.SrcIP,
				DstIP:      key.DstIP,
				DstPort:    key.DstPort,
				Protocol:   key.Proto,
				BytesOut:   flow.Bytes,
				Duration:   duration,
				Rate:       uploadRate,
				Method:     method,
				Confidence: confidence,
			})
		}
	}
	
	fmt.Printf("  - Found %d exfiltration patterns\n", len(exfils))
	return exfils
}

func (a *Analyzer) addExfiltrationThreats(exfils []DataExfiltration) {
	for _, exfil := range exfils {
		severity := "low"
		if exfil.Confidence == "high" {
			severity = "high"
		} else if exfil.Confidence == "medium" {
			severity = "medium"
		}
		
		// Format bytes in human-readable format (use formatBytes from anomalies.go)
		bytesStr := formatBytes(exfil.BytesOut)
		rateStr := formatBytes(int64(exfil.Rate)) + "/s"
		
		a.addThreat(Threat{
			Type:     "Data Exfiltration",
			Severity: severity,
			Detail: fmt.Sprintf("%s: %s -> %s:%d (%s transferred at %s over %v)",
				exfil.Method, exfil.SrcIP, exfil.DstIP, exfil.DstPort,
				bytesStr, rateStr, exfil.Duration.Round(time.Second)),
			IOC: fmt.Sprintf("%s:%d", exfil.DstIP, exfil.DstPort),
		})
	}
}
