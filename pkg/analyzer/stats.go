package analyzer

import (
	"fmt"
	"sort"
	"time"
)

func (a *Analyzer) calculateStatistics() {
	fmt.Println("Calculating statistics...")
	
	a.mu.Lock()
	
	// Set total packets from processed counter
	a.stats.TotalPackets = a.processed
	
	fmt.Println("  - Calculating total bytes...")
	// Total bytes from flows
	a.stats.TotalBytes = 0
	for _, flow := range a.flows {
		a.stats.TotalBytes += flow.Bytes
	}

	fmt.Println("  - Calculating duration...")
	// Duration from flows
	var minTime, maxTime time.Time
	first := true
	for _, flow := range a.flows {
		if first {
			minTime = flow.StartTime
			maxTime = flow.EndTime
			first = false
		} else {
			if flow.StartTime.Before(minTime) {
				minTime = flow.StartTime
			}
			if flow.EndTime.After(maxTime) {
				maxTime = flow.EndTime
			}
		}
	}
	if !first {
		a.stats.Duration = maxTime.Sub(minTime)
	}

	fmt.Println("  - Calculating protocol distribution...")
	// Protocol distribution from flows
	a.stats.Protocols = make(map[string]int64)
	for key, flow := range a.flows {
		a.stats.Protocols[key.Proto] += flow.Packets
	}

	fmt.Println("  - Calculating top talkers...")
	// Top talkers from flows (limit to reduce processing time)
	talkers := make(map[string]*TalkerInfo)
	count := 0
	maxTalkers := 1000 // Limit to prevent excessive processing
	
	for key, flow := range a.flows {
		if count >= maxTalkers {
			break
		}
		if _, exists := talkers[key.SrcIP]; !exists {
			talkers[key.SrcIP] = &TalkerInfo{IP: key.SrcIP}
		}
		talkers[key.SrcIP].Packets += flow.Packets
		talkers[key.SrcIP].Bytes += flow.Bytes
		count++
	}

	fmt.Println("  - Sorting top talkers...")
	// Convert to slice and sort
	for _, talker := range talkers {
		a.stats.TopTalkers = append(a.stats.TopTalkers, *talker)
	}
	sort.Slice(a.stats.TopTalkers, func(i, j int) bool {
		return a.stats.TopTalkers[i].Bytes > a.stats.TopTalkers[j].Bytes
	})

	// Keep top 10
	if len(a.stats.TopTalkers) > 10 {
		a.stats.TopTalkers = a.stats.TopTalkers[:10]
	}

	fmt.Println("  - Calculating threat score...")
	// Calculate threat score
	a.stats.ThreatScore = a.calculateThreatScore()
	
	a.mu.Unlock()
	
	fmt.Println("Statistics calculation complete!")
}

func (a *Analyzer) calculateThreatScore() float64 {
	if len(a.threats) == 0 {
		return 0.0
	}

	// Count threats by severity
	highCount := 0
	mediumCount := 0
	lowCount := 0
	
	for _, threat := range a.threats {
		switch threat.Severity {
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
	}
	
	// Balanced scoring with logarithmic scaling
	// Prevents both easy saturation and undervaluation
	
	score := 0.0
	
	// High severity threats (max 50 points)
	// 1 high = 15, 10 high = 30, 100 high = 40, 1000+ high = 50
	if highCount > 0 {
		if highCount == 1 {
			score += 15.0
		} else if highCount < 10 {
			score += 15.0 + (float64(highCount-1) * 1.67) // Linear up to 10
		} else {
			// Logarithmic after 10
			highScore := 30.0 + (logScale(float64(highCount), 20.0, 3.0) * 0.67)
			score += highScore
		}
	}
	
	// Medium severity threats (max 30 points)
	// 1 medium = 5, 10 medium = 15, 100 medium = 23, 1000+ medium = 30
	if mediumCount > 0 {
		if mediumCount == 1 {
			score += 5.0
		} else if mediumCount < 10 {
			score += 5.0 + (float64(mediumCount-1) * 1.11) // Linear up to 10
		} else {
			mediumScore := 15.0 + (logScale(float64(mediumCount), 15.0, 3.0) * 0.5)
			score += mediumScore
		}
	}
	
	// Low severity threats (max 20 points)
	// 1 low = 1, 10 low = 5, 100 low = 12, 1000+ low = 20
	if lowCount > 0 {
		if lowCount == 1 {
			score += 1.0
		} else if lowCount < 10 {
			score += 1.0 + (float64(lowCount-1) * 0.44) // Linear up to 10
		} else {
			lowScore := 5.0 + (logScale(float64(lowCount), 15.0, 3.0) * 0.5)
			score += lowScore
		}
	}
	
	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// logScale applies logarithmic scaling to prevent score saturation
// count: number of items
// multiplier: scaling factor
// maxLog: maximum log value (e.g., 3.0 for log10(1000) = 3)
func logScale(count float64, multiplier float64, maxLog float64) float64 {
	if count <= 0 {
		return 0
	}
	// log10(count+1) / maxLog * multiplier
	// This gives diminishing returns as count increases
	logValue := log10(count + 1)
	if logValue > maxLog {
		logValue = maxLog
	}
	return (logValue / maxLog) * multiplier
}

// log10 calculates base-10 logarithm
func log10(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// log10(x) = ln(x) / ln(10)
	return logNatural(x) / 2.302585092994046 // ln(10)
}

// logNatural calculates natural logarithm using Taylor series
func logNatural(x float64) float64 {
	if x <= 0 {
		return 0
	}
	if x == 1 {
		return 0
	}
	
	// For better convergence, use ln(x) = ln(x/e^k) + k where e^k is close to x
	// Simple approximation for our use case
	if x > 2 {
		// ln(x) = ln(x/2) + ln(2)
		return logNatural(x/2) + 0.693147180559945 // ln(2)
	}
	
	// Taylor series: ln(1+x) = x - x^2/2 + x^3/3 - x^4/4 + ...
	// For x close to 1, use ln(x) = ln(1 + (x-1))
	z := x - 1
	if z < -0.5 || z > 0.5 {
		// Use different approach for values far from 1
		return logNatural(x/1.5) + 0.405465108108164 // ln(1.5)
	}
	
	sum := 0.0
	term := z
	for i := 1; i <= 20; i++ {
		if i%2 == 1 {
			sum += term / float64(i)
		} else {
			sum -= term / float64(i)
		}
		term *= z
	}
	
	return sum
}
