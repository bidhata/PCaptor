package analyzer

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// StegoDetection represents detected steganography
type StegoDetection struct {
	Timestamp   time.Time
	Protocol    string
	Filename    string
	FileType    string
	Indicator   string
	Confidence  string
	SrcIP       string
	DstIP       string
	Method      string
}

func (a *Analyzer) detectSteganography(data []byte, filename string, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.stegoDetections) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	if len(data) < 100 {
		return
	}

	// Check for common stego tool signatures
	stegoSignatures := map[string]string{
		"steghide":  "Steghide",
		"outguess":  "OutGuess",
		"jphide":    "JPHide",
		"jsteg":     "JSteg",
		"f5":        "F5 Algorithm",
		"openstego": "OpenStego",
		"stegano":   "Stegano",
	}
	
	dataStr := strings.ToLower(string(data))
	for sig, tool := range stegoSignatures {
		if strings.Contains(dataStr, sig) {
			a.addStegoDetection(StegoDetection{
				Timestamp:  info.Timestamp,
				Protocol:   info.Protocol,
				Filename:   filename,
				Indicator:  "Steganography tool signature detected",
				Confidence: "high",
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				Method:     tool,
			})
			return
		}
	}
	
	// Detect file type from magic bytes
	fileType := detectFileType(data)
	
	// Check for LSB steganography in images
	if fileType == "PNG" || fileType == "BMP" || fileType == "JPEG" {
		if len(data) > 1000 {
			lsbEntropy := calculateLSBEntropy(data)
			
			// High LSB entropy indicates possible steganography
			if lsbEntropy > 0.7 {
				a.addStegoDetection(StegoDetection{
					Timestamp:  info.Timestamp,
					Protocol:   info.Protocol,
					Filename:   filename,
					FileType:   fileType,
					Indicator:  fmt.Sprintf("High LSB entropy detected (%.2f)", lsbEntropy),
					Confidence: "medium",
					SrcIP:      info.SrcIP,
					DstIP:      info.DstIP,
					Method:     "LSB Steganography",
				})
			}
		}
	}
	
	// Check for hidden data in file metadata/comments
	if bytes.Contains(data, []byte("Comment:")) || bytes.Contains(data, []byte("comment:")) {
		// Extract comment section
		commentIdx := bytes.Index(data, []byte("omment:"))
		if commentIdx != -1 && commentIdx+100 < len(data) {
			commentData := data[commentIdx : commentIdx+100]
			commentEntropy := calculateEntropy(commentData)
			
			if commentEntropy > 0.8 {
				a.addStegoDetection(StegoDetection{
					Timestamp:  info.Timestamp,
					Protocol:   info.Protocol,
					Filename:   filename,
					FileType:   fileType,
					Indicator:  "High entropy in file metadata/comments",
					Confidence: "low",
					SrcIP:      info.SrcIP,
					DstIP:      info.DstIP,
					Method:     "Metadata Steganography",
				})
			}
		}
	}
}

func detectFileType(data []byte) string {
	if len(data) < 4 {
		return "Unknown"
	}
	
	// Check magic bytes
	switch {
	case bytes.HasPrefix(data, []byte{0x89, 0x50, 0x4E, 0x47}):
		return "PNG"
	case bytes.HasPrefix(data, []byte{0xFF, 0xD8, 0xFF}):
		return "JPEG"
	case bytes.HasPrefix(data, []byte{0x42, 0x4D}):
		return "BMP"
	case bytes.HasPrefix(data, []byte{0x47, 0x49, 0x46}):
		return "GIF"
	case bytes.HasPrefix(data, []byte{0x25, 0x50, 0x44, 0x46}):
		return "PDF"
	case bytes.HasPrefix(data, []byte{0x50, 0x4B, 0x03, 0x04}):
		return "ZIP"
	case bytes.HasPrefix(data, []byte{0x52, 0x61, 0x72, 0x21}):
		return "RAR"
	default:
		return "Unknown"
	}
}

func calculateLSBEntropy(data []byte) float64 {
	if len(data) < 100 {
		return 0
	}
	
	// Extract LSBs
	lsbs := make([]byte, 0, len(data))
	for _, b := range data {
		lsbs = append(lsbs, b&1)
	}
	
	// Calculate entropy of LSBs
	return calculateEntropy(lsbs)
}

func (a *Analyzer) addStegoDetection(detection StegoDetection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	
	if len(a.stegoDetections) < a.maxMessages {
		a.stegoDetections = append(a.stegoDetections, detection)
		
		// Add as threat
		severity := "low"
		if detection.Confidence == "high" {
			severity = "medium"
		}
		
		a.addThreatUnlocked(Threat{
			Type:     "Steganography",
			Severity: severity,
			Detail:   fmt.Sprintf("%s in %s: %s", detection.Method, detection.Filename, detection.Indicator),
			IOC:      detection.Filename,
		})
	}
}

func (a *Analyzer) addThreatUnlocked(threat Threat) {
	if len(a.threats) < a.maxMessages {
		a.threats = append(a.threats, threat)
	}
}
