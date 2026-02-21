package analyzer

import (
	"fmt"
	"math"
	"time"
)

// BeaconPattern represents a detected beaconing pattern
type BeaconPattern struct {
	FlowKey     FlowKey
	Interval    time.Duration
	Jitter      float64
	Confidence  string
	PacketCount int
	StartTime   time.Time
	EndTime     time.Time
	BytesTotal  int64
}

func (a *Analyzer) detectAnomalies() {
	a.detectPortScans()
	a.detectBeaconing()
	a.detectDataExfiltration()
}

func (a *Analyzer) detectPortScans() {
	// Track ports scanned by each source
	srcToDstPorts := make(map[string]map[string]map[uint16]bool)

	a.mu.RLock()
	for key := range a.flows {
		if _, exists := srcToDstPorts[key.SrcIP]; !exists {
			srcToDstPorts[key.SrcIP] = make(map[string]map[uint16]bool)
		}
		if _, exists := srcToDstPorts[key.SrcIP][key.DstIP]; !exists {
			srcToDstPorts[key.SrcIP][key.DstIP] = make(map[uint16]bool)
		}
		srcToDstPorts[key.SrcIP][key.DstIP][key.DstPort] = true
	}
	a.mu.RUnlock()

	// Detect scans (>20 ports)
	for srcIP, dstMap := range srcToDstPorts {
		for dstIP, ports := range dstMap {
			if len(ports) >= 20 {
				a.addThreat(Threat{
					Type:     "Port Scan Detected",
					Severity: "high",
					Detail:   srcIP + " scanned " + string(rune(len(ports))) + " ports on " + dstIP,
					IOC:      srcIP,
				})
			}
		}
	}
}

func (a *Analyzer) detectBeaconing() []BeaconPattern {
	fmt.Println("Detecting beaconing patterns...")
	
	beacons := []BeaconPattern{}
	
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	for key, flow := range a.flows {
		if len(flow.Timestamps) < 10 {
			continue // Need at least 10 packets for statistical analysis
		}
		
		// Calculate intervals between packets
		intervals := []float64{}
		for i := 1; i < len(flow.Timestamps); i++ {
			interval := flow.Timestamps[i].Sub(flow.Timestamps[i-1]).Seconds()
			intervals = append(intervals, interval)
		}
		
		if len(intervals) < 5 {
			continue
		}
		
		// Calculate mean interval
		mean := calculateMeanFloat(intervals)
		
		// Skip if mean is too short (<1s) or too long (>1 hour)
		if mean < 1.0 || mean > 3600.0 {
			continue
		}
		
		// Calculate standard deviation
		stdDev := calculateStdDevFloat(intervals, mean)
		
		// Calculate jitter (coefficient of variation)
		jitter := stdDev / mean
		
		// Low jitter indicates beaconing
		// Jitter < 0.3 is highly suspicious
		// Jitter < 0.5 is suspicious
		if jitter < 0.5 {
			confidence := "low"
			if jitter < 0.15 {
				confidence = "high"
			} else if jitter < 0.3 {
				confidence = "medium"
			}
			
			beacon := BeaconPattern{
				FlowKey:     key,
				Interval:    time.Duration(mean * float64(time.Second)),
				Jitter:      jitter,
				Confidence:  confidence,
				PacketCount: len(flow.Timestamps),
				StartTime:   flow.StartTime,
				EndTime:     flow.EndTime,
				BytesTotal:  flow.Bytes,
			}
			
			beacons = append(beacons, beacon)
		}
	}
	
	fmt.Printf("  - Found %d beaconing patterns\n", len(beacons))
	return beacons
}

func calculateMeanFloat(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculateStdDevFloat(values []float64, mean float64) float64 {
	if len(values) == 0 {
		return 0
	}
	
	variance := 0.0
	for _, v := range values {
		diff := v - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	
	return math.Sqrt(variance)
}

func (a *Analyzer) detectDataExfiltration() {
	a.mu.RLock()
	
	// Collect threats while holding read lock
	var threats []Threat
	
	for key, flow := range a.flows {
		// Large outbound transfers (>10MB)
		if flow.Bytes > 10_000_000 {
			threats = append(threats, Threat{
				Type:     "Large Data Transfer",
				Severity: "medium",
				Detail:   key.SrcIP + " -> " + key.DstIP + " transferred " + formatBytes(flow.Bytes),
				IOC:      key.DstIP,
			})
		}
	}
	
	a.mu.RUnlock()
	
	// Add threats after releasing read lock
	for _, threat := range threats {
		a.addThreat(threat)
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return string(rune(bytes)) + " B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return string(rune(bytes/div)) + " " + "KMGTPE"[exp:exp+1] + "B"
}


func (a *Analyzer) addBeaconThreats(beacons []BeaconPattern) {
	for _, beacon := range beacons {
		severity := "low"
		if beacon.Confidence == "high" {
			severity = "high"
		} else if beacon.Confidence == "medium" {
			severity = "medium"
		}
		
		a.addThreat(Threat{
			Type:     "C2 Beaconing",
			Severity: severity,
			Detail: fmt.Sprintf("Beaconing detected: %s -> %s:%d (Interval: %v, Jitter: %.2f, Packets: %d)",
				beacon.FlowKey.SrcIP, beacon.FlowKey.DstIP, beacon.FlowKey.DstPort,
				beacon.Interval, beacon.Jitter, beacon.PacketCount),
			IOC: fmt.Sprintf("%s:%d", beacon.FlowKey.DstIP, beacon.FlowKey.DstPort),
		})
	}
}
