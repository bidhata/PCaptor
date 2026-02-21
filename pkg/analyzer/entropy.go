package analyzer

import (
	"fmt"
	"math"
)

// calculateEntropy calculates Shannon entropy of data (0-1 normalized)
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}
	
	entropy := 0.0
	length := float64(len(data))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	// Normalize to 0-1 (max entropy for byte is 8 bits)
	return entropy / 8.0
}

// analyzePayloadEntropy detects encrypted/packed payloads
func (a *Analyzer) analyzePayloadEntropy(payload []byte, info PacketInfo) {
	if len(payload) < 100 {
		return
	}
	
	entropy := calculateEntropy(payload)
	
	// High entropy indicates encryption/packing
	// Entropy > 0.9 is very suspicious
	// Entropy > 0.95 is almost certainly encrypted
	if entropy > 0.9 {
		severity := "low"
		confidence := "low"
		
		if entropy > 0.95 {
			severity = "medium"
			confidence = "high"
		} else if entropy > 0.92 {
			confidence = "medium"
		}
		
		a.addThreat(Threat{
			Type:     "Encrypted Payload",
			Severity: severity,
			Detail:   fmt.Sprintf("High entropy payload detected (%.3f) - possible encryption/packing (%s confidence)", entropy, confidence),
			IOC:      fmt.Sprintf("%s -> %s:%d", info.SrcIP, info.DstIP, info.DstPort),
		})
	}
}
