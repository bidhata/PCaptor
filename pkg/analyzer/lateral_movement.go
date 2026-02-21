package analyzer

import (
	"fmt"
	"time"
)

// LateralMovement represents detected lateral movement activity
type LateralMovement struct {
	Timestamp   time.Time
	SrcIP       string
	Targets     []string
	Protocol    string
	Port        uint16
	Technique   string
	Confidence  string
	TargetCount int
}

func (a *Analyzer) detectLateralMovement() []LateralMovement {
	fmt.Println("Detecting lateral movement...")
	
	movements := []LateralMovement{}
	
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	// Track connections per source IP
	srcConnections := make(map[string]map[uint16]map[string]bool)
	srcTimestamps := make(map[string]time.Time)
	
	for key, flow := range a.flows {
		if _, exists := srcConnections[key.SrcIP]; !exists {
			srcConnections[key.SrcIP] = make(map[uint16]map[string]bool)
			srcTimestamps[key.SrcIP] = flow.StartTime
		}
		
		if _, exists := srcConnections[key.SrcIP][key.DstPort]; !exists {
			srcConnections[key.SrcIP][key.DstPort] = make(map[string]bool)
		}
		
		srcConnections[key.SrcIP][key.DstPort][key.DstIP] = true
		
		// Update timestamp to earliest
		if flow.StartTime.Before(srcTimestamps[key.SrcIP]) {
			srcTimestamps[key.SrcIP] = flow.StartTime
		}
	}
	
	// Detect patterns - ports commonly used for lateral movement
	lateralPorts := map[uint16]string{
		445:  "SMB lateral movement (PsExec/WMI/DCOM)",
		3389: "RDP lateral movement",
		22:   "SSH lateral movement",
		5985: "WinRM lateral movement (HTTP)",
		5986: "WinRM lateral movement (HTTPS)",
		135:  "RPC/DCOM lateral movement",
		139:  "NetBIOS lateral movement",
		1433: "MSSQL lateral movement",
		3306: "MySQL lateral movement",
		5432: "PostgreSQL lateral movement",
	}
	
	for srcIP, portMap := range srcConnections {
		for port, targets := range portMap {
			technique, isLateralPort := lateralPorts[port]
			
			if !isLateralPort {
				continue
			}
			
			targetCount := len(targets)
			
			// Multiple targets on same port indicates lateral movement
			if targetCount >= 3 {
				confidence := "low"
				if targetCount >= 10 {
					confidence = "high"
				} else if targetCount >= 5 {
					confidence = "medium"
				}
				
				targetList := []string{}
				for target := range targets {
					targetList = append(targetList, target)
					if len(targetList) >= 20 {
						break // Limit to 20 for display
					}
				}
				
				movements = append(movements, LateralMovement{
					Timestamp:   srcTimestamps[srcIP],
					SrcIP:       srcIP,
					Targets:     targetList,
					Protocol:    "TCP",
					Port:        port,
					Technique:   technique,
					Confidence:  confidence,
					TargetCount: targetCount,
				})
			}
		}
	}
	
	fmt.Printf("  - Found %d lateral movement patterns\n", len(movements))
	return movements
}

func (a *Analyzer) addLateralMovementThreats(movements []LateralMovement) {
	for _, movement := range movements {
		severity := "low"
		if movement.Confidence == "high" {
			severity = "high"
		} else if movement.Confidence == "medium" {
			severity = "medium"
		}
		
		targetSummary := ""
		if len(movement.Targets) > 5 {
			targetSummary = fmt.Sprintf("%s, %s, %s, ... (%d total)",
				movement.Targets[0], movement.Targets[1], movement.Targets[2], movement.TargetCount)
		} else {
			for i, target := range movement.Targets {
				if i > 0 {
					targetSummary += ", "
				}
				targetSummary += target
			}
		}
		
		a.addThreat(Threat{
			Type:     "Lateral Movement",
			Severity: severity,
			Detail: fmt.Sprintf("%s from %s to %d targets on port %d: %s",
				movement.Technique, movement.SrcIP, movement.TargetCount, movement.Port, targetSummary),
			IOC: fmt.Sprintf("%s -> port %d", movement.SrcIP, movement.Port),
		})
	}
}
