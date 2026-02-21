package analyzer

import (
	"fmt"
	"time"
)

// SSHTunnel represents a detected SSH tunnel
type SSHTunnel struct {
	Timestamp      time.Time
	SrcIP          string
	DstIP          string
	SrcPort        uint16
	DstPort        uint16
	BytesPerSecond float64
	PacketRate     float64
	Duration       float64
	TotalBytes     int64
	TotalPackets   int64
	Suspicious     bool
	Reason         string
	Confidence     string
}

// ICMPTunnel represents a detected ICMP tunnel
type ICMPTunnel struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	Type        uint8
	Code        uint8
	PayloadSize int
	Entropy     float64
	Suspicious  bool
	Reason      string
	Confidence  string
}

func (a *Analyzer) detectSSHTunneling() []SSHTunnel {
	fmt.Println("Detecting SSH tunneling...")
	
	tunnels := []SSHTunnel{}
	
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	for key, flow := range a.flows {
		// SSH is typically port 22
		if key.DstPort != 22 && key.SrcPort != 22 {
			continue
		}
		
		duration := flow.EndTime.Sub(flow.StartTime).Seconds()
		if duration < 1 {
			continue
		}
		
		bytesPerSec := float64(flow.Bytes) / duration
		packetRate := float64(flow.Packets) / duration
		
		suspicious := false
		reason := ""
		confidence := "low"
		
		// High throughput SSH (possible tunnel)
		if bytesPerSec > 100000 { // >100KB/s
			suspicious = true
			reason = "High throughput SSH connection (possible tunnel)"
			confidence = "high"
		}
		
		// High packet rate (possible interactive tunnel)
		if packetRate > 50 {
			suspicious = true
			if reason != "" {
				reason += " + High packet rate"
			} else {
				reason = "High packet rate SSH (possible interactive tunnel)"
			}
			confidence = "medium"
		}
		
		// Long-lived SSH connection
		if duration > 3600 { // >1 hour
			suspicious = true
			if reason != "" {
				reason += " + Long-lived connection"
			} else {
				reason = "Long-lived SSH connection (possible persistent tunnel)"
			}
			if confidence == "low" {
				confidence = "medium"
			}
		}
		
		// Unusual SSH traffic pattern (many small packets)
		if flow.Packets > 1000 && bytesPerSec < 10000 {
			suspicious = true
			if reason != "" {
				reason += " + Unusual traffic pattern"
			} else {
				reason = "Unusual SSH traffic pattern (many small packets)"
			}
		}
		
		if suspicious {
			tunnels = append(tunnels, SSHTunnel{
				Timestamp:      flow.StartTime,
				SrcIP:          key.SrcIP,
				DstIP:          key.DstIP,
				SrcPort:        key.SrcPort,
				DstPort:        key.DstPort,
				BytesPerSecond: bytesPerSec,
				PacketRate:     packetRate,
				Duration:       duration,
				TotalBytes:     flow.Bytes,
				TotalPackets:   flow.Packets,
				Suspicious:     true,
				Reason:         reason,
				Confidence:     confidence,
			})
		}
	}
	
	fmt.Printf("  - Found %d SSH tunnels\n", len(tunnels))
	return tunnels
}

func (a *Analyzer) parseICMP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.icmpTunnels) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	if len(payload) < 8 {
		return
	}
	
	// ICMP Type and Code
	icmpType := payload[0]
	icmpCode := payload[1]
	
	// Echo Request/Reply (Type 8/0)
	if icmpType == 8 || icmpType == 0 {
		// Normal ping is 32-64 bytes, suspicious if larger
		if len(payload) > 100 {
			entropy := calculateEntropy(payload[8:])
			
			suspicious := false
			reason := ""
			confidence := "low"
			
			// High entropy indicates encrypted/encoded data
			if entropy > 0.7 {
				suspicious = true
				reason = "Large ICMP payload with high entropy (possible tunnel)"
				confidence = "high"
			} else if len(payload) > 200 {
				suspicious = true
				reason = "Unusually large ICMP payload (possible tunnel)"
				confidence = "medium"
			}
			
			if suspicious {
				tunnel := ICMPTunnel{
					Timestamp:   info.Timestamp,
					SrcIP:       info.SrcIP,
					DstIP:       info.DstIP,
					Type:        icmpType,
					Code:        icmpCode,
					PayloadSize: len(payload),
					Entropy:     entropy,
					Suspicious:  true,
					Reason:      reason,
					Confidence:  confidence,
				}
				
				a.addICMPTunnel(tunnel)
				
				a.addThreat(Threat{
					Type:     "ICMP Tunneling",
					Severity: "medium",
					Detail:   fmt.Sprintf("%s: %d bytes, entropy: %.2f", reason, len(payload), entropy),
					IOC:      fmt.Sprintf("%s -> %s", info.SrcIP, info.DstIP),
				})
			}
		}
	}
}

func (a *Analyzer) addSSHTunnelThreats(tunnels []SSHTunnel) {
	for _, tunnel := range tunnels {
		severity := "low"
		if tunnel.Confidence == "high" {
			severity = "high"
		} else if tunnel.Confidence == "medium" {
			severity = "medium"
		}
		
		a.addThreat(Threat{
			Type:     "SSH Tunneling",
			Severity: severity,
			Detail: fmt.Sprintf("%s: %s -> %s:%d (%.0f KB/s, %.0f pkt/s, %.0f sec)",
				tunnel.Reason, tunnel.SrcIP, tunnel.DstIP, tunnel.DstPort,
				tunnel.BytesPerSecond/1024, tunnel.PacketRate, tunnel.Duration),
			IOC: fmt.Sprintf("%s:%d", tunnel.DstIP, tunnel.DstPort),
		})
	}
}

func (a *Analyzer) addICMPTunnel(tunnel ICMPTunnel) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.icmpTunnels) < a.maxMessages {
		a.icmpTunnels = append(a.icmpTunnels, tunnel)
	}
}
