package analyzer

import (
	"fmt"
	"strings"
)

// Anonymization represents detected anonymization/VPN usage
type Anonymization struct {
	Timestamp  string
	SrcIP      string
	DstIP      string
	DstPort    uint16
	Type       string
	Confidence string
}

// Known Tor ports
var torPorts = []uint16{
	9001,  // Tor relay
	9030,  // Tor directory
	9050,  // Tor SOCKS proxy
	9051,  // Tor control port
	9150,  // Tor Browser SOCKS proxy
}

// VPN ports and protocols
var vpnPorts = map[uint16]string{
	1194: "OpenVPN",
	1723: "PPTP VPN",
	500:  "IPSec VPN (IKE)",
	4500: "IPSec NAT-T",
	1701: "L2TP VPN",
}

// Known VPN/Proxy providers
var vpnProviders = []string{
	"nordvpn",
	"expressvpn",
	"protonvpn",
	"mullvad",
	"privateinternetaccess",
	"pia-",
	"cyberghost",
	"surfshark",
	"ipvanish",
	"tunnelbear",
	"windscribe",
	"vyprvpn",
	"torguard",
	"purevpn",
	"hidemyass",
	"proxy.sh",
	"proxychains",
}

func (a *Analyzer) detectTorVPN(host string, dstIP string, dstPort uint16, info PacketInfo) {
	hostLower := strings.ToLower(host)
	
	// Check for Tor ports
	for _, port := range torPorts {
		if dstPort == port {
			a.addThreat(Threat{
				Type:     "Anonymization",
				Severity: "medium",
				Detail:   fmt.Sprintf("Tor network connection detected (port %d)", port),
				IOC:      fmt.Sprintf("%s:%d", dstIP, port),
			})
			return
		}
	}
	
	// Check for VPN ports
	if vpnName, exists := vpnPorts[dstPort]; exists {
		a.addThreat(Threat{
			Type:     "VPN Connection",
			Severity: "low",
			Detail:   fmt.Sprintf("%s connection detected", vpnName),
			IOC:      fmt.Sprintf("%s:%d", dstIP, dstPort),
		})
		return
	}
	
	// Check for VPN provider domains
	for _, provider := range vpnProviders {
		if strings.Contains(hostLower, provider) {
			a.addThreat(Threat{
				Type:     "VPN Connection",
				Severity: "low",
				Detail:   fmt.Sprintf("VPN provider detected: %s", provider),
				IOC:      host,
			})
			return
		}
	}
	
	// Check for Tor in hostname
	if strings.Contains(hostLower, ".onion") {
		a.addThreat(Threat{
			Type:     "Anonymization",
			Severity: "high",
			Detail:   "Tor hidden service (.onion) access detected",
			IOC:      host,
		})
		return
	}
	
	// Check for proxy keywords
	proxyKeywords := []string{"proxy", "socks", "vpn", "tunnel"}
	for _, keyword := range proxyKeywords {
		if strings.Contains(hostLower, keyword) {
			a.addThreat(Threat{
				Type:     "Proxy Connection",
				Severity: "low",
				Detail:   fmt.Sprintf("Proxy/tunnel keyword detected in hostname: %s", keyword),
				IOC:      host,
			})
			return
		}
	}
}

func (a *Analyzer) detectSOCKSProxy(payload []byte, info PacketInfo) {
	if len(payload) < 3 {
		return
	}
	
	// SOCKS4/5 handshake detection
	// SOCKS5: 0x05 (version) + 0x01-0xFF (number of methods)
	// SOCKS4: 0x04 (version) + 0x01 (connect)
	
	if payload[0] == 0x05 {
		// SOCKS5
		a.addThreat(Threat{
			Type:     "Proxy Connection",
			Severity: "medium",
			Detail:   "SOCKS5 proxy connection detected",
			IOC:      fmt.Sprintf("%s -> %s:%d", info.SrcIP, info.DstIP, info.DstPort),
		})
	} else if payload[0] == 0x04 && payload[1] == 0x01 {
		// SOCKS4
		a.addThreat(Threat{
			Type:     "Proxy Connection",
			Severity: "medium",
			Detail:   "SOCKS4 proxy connection detected",
			IOC:      fmt.Sprintf("%s -> %s:%d", info.SrcIP, info.DstIP, info.DstPort),
		})
	}
}
