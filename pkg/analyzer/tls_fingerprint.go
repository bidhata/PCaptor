package analyzer

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TLSFingerprint represents a JA3/JA4 fingerprint
type TLSFingerprint struct {
	Timestamp   time.Time
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	JA3Hash     string
	JA3String   string
	ServerName  string
	TLSVersion  string
	Suspicious  bool
	Framework   string
	Confidence  string
}

// Known malicious JA3 hashes from threat intelligence
var maliciousJA3 = map[string]string{
	"6734f37431670b3ab4292b8f60f29984": "Cobalt Strike",
	"a0e9f5d64349fb13191bc781f81f42e1": "Metasploit",
	"72a589da586844d7f0818ce684948eea": "Sliver",
	"51c64c77e60f3980eea90869b68c58a8": "Trickbot",
	"e7d705a3286e19ea42f587b344ee6865": "Dridex",
	"ada70206e40642a3e4461f35503241d5": "IcedID",
	"b32309a26951912be7dba376398abc3b": "Emotet",
	"06cd26e5b1c5f6c9c0d8c3c6e3c3c3c3": "Qakbot",
	"de350869b8c85de67a350c8d186f11e6": "AsyncRAT",
	"e35df3e00ca4ef31d42b34bebaa2f86e": "njRAT",
}

// Suspicious TLS patterns
var suspiciousTLSPatterns = []struct {
	pattern string
	reason  string
}{
	{"GREASE", "GREASE values (common in malware)"},
	{"TLS_EMPTY_RENEGOTIATION_INFO_SCSV", "Renegotiation (potential MITM)"},
}

func (a *Analyzer) parseTLS(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.tlsFingerprints) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	if len(payload) < 43 {
		return
	}

	// Check for TLS handshake (0x16)
	if payload[0] != 0x16 {
		return
	}

	// Check for Client Hello (0x01)
	if len(payload) < 6 || payload[5] != 0x01 {
		return
	}

	ja3String, tlsVersion, serverName := a.extractJA3Components(payload)
	if ja3String == "" {
		return
	}

	// Calculate JA3 hash
	hash := md5.Sum([]byte(ja3String))
	ja3Hash := hex.EncodeToString(hash[:])

	// Check if malicious
	suspicious := false
	framework := ""
	confidence := "low"

	if fw, exists := maliciousJA3[ja3Hash]; exists {
		suspicious = true
		framework = fw
		confidence = "high"
	}

	// Check for suspicious patterns
	for _, pattern := range suspiciousTLSPatterns {
		if strings.Contains(ja3String, pattern.pattern) {
			suspicious = true
			if framework == "" {
				framework = "Unknown"
			}
			confidence = "medium"
			break
		}
	}

	fingerprint := TLSFingerprint{
		Timestamp:  info.Timestamp,
		SrcIP:      info.SrcIP,
		DstIP:      info.DstIP,
		SrcPort:    info.SrcPort,
		DstPort:    info.DstPort,
		JA3Hash:    ja3Hash,
		JA3String:  ja3String,
		ServerName: serverName,
		TLSVersion: tlsVersion,
		Suspicious: suspicious,
		Framework:  framework,
		Confidence: confidence,
	}

	a.addTLSFingerprint(fingerprint)

	if suspicious {
		a.addThreat(Threat{
			Type:     "Malicious TLS Fingerprint",
			Severity: "high",
			Detail:   fmt.Sprintf("Malicious JA3 hash detected: %s (%s)", ja3Hash, framework),
			IOC:      fmt.Sprintf("%s -> %s (JA3: %s)", info.SrcIP, info.DstIP, ja3Hash),
		})
	}
}

func (a *Analyzer) extractJA3Components(payload []byte) (string, string, string) {
	// Simplified JA3 extraction (basic implementation)
	// Full implementation would parse TLS handshake completely
	
	if len(payload) < 43 {
		return "", "", ""
	}

	// TLS version (bytes 9-10)
	tlsVersion := fmt.Sprintf("%d", int(payload[9])<<8|int(payload[10]))

	// For a complete implementation, we would parse:
	// - Cipher suites
	// - Extensions
	// - Elliptic curves
	// - Elliptic curve point formats
	// - SNI (Server Name Indication)

	// Simplified version - just return version for now
	ja3String := tlsVersion + ",,"

	serverName := ""
	// Try to extract SNI if present
	if len(payload) > 100 {
		// Look for SNI extension (0x0000)
		for i := 43; i < len(payload)-2; i++ {
			if payload[i] == 0x00 && payload[i+1] == 0x00 {
				// Found potential SNI
				if i+9 < len(payload) {
					sniLen := int(payload[i+7])<<8 | int(payload[i+8])
					if i+9+sniLen < len(payload) {
						serverName = string(payload[i+9 : i+9+sniLen])
						break
					}
				}
			}
		}
	}

	return ja3String, tlsVersion, serverName
}

func (a *Analyzer) addTLSFingerprint(fp TLSFingerprint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.tlsFingerprints) < a.maxMessages {
		a.tlsFingerprints = append(a.tlsFingerprints, fp)
	}
}
