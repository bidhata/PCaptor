package analyzer

import (
	"fmt"
	"strings"
)

// CryptoMining represents detected cryptocurrency mining activity
type CryptoMining struct {
	Timestamp  string
	SrcIP      string
	DstIP      string
	DstPort    uint16
	Pool       string
	Protocol   string
	Confidence string
}

// Known mining pools and patterns
var miningPools = []string{
	"pool.supportxmr.com",
	"xmr-eu1.nanopool.org",
	"xmr-us-east1.nanopool.org",
	"xmr-us-west1.nanopool.org",
	"xmr-asia1.nanopool.org",
	"pool.minexmr.com",
	"monero.crypto-pool.fr",
	"xmr.pool.minergate.com",
	"monerohash.com",
	"moneroocean.stream",
	"gulf.moneroocean.stream",
	"xmrpool.eu",
	"xmr.nanopool.org",
	"mine.xmrpool.net",
	"pool.xmr.pt",
	"stratum+tcp://",
	"stratum+ssl://",
	"stratum://",
	"nicehash.com",
	"miningpoolhub.com",
	"ethermine.org",
	"f2pool.com",
	"antpool.com",
	"slushpool.com",
	"btc.com",
}

var miningKeywords = []string{
	"xmrig",
	"xmr-stak",
	"claymore",
	"phoenixminer",
	"ethminer",
	"cgminer",
	"bfgminer",
	"ccminer",
	"cryptonight",
	"randomx",
	"ethash",
	"equihash",
}

// Common mining ports
var miningPorts = []uint16{
	3333,  // Stratum
	4444,  // Stratum
	5555,  // Stratum
	7777,  // Stratum
	8888,  // Stratum
	9999,  // Stratum
	14444, // XMR
	45700, // XMR
}

func (a *Analyzer) detectCryptoMining(host, url, userAgent string, info PacketInfo) {
	hostLower := strings.ToLower(host)
	urlLower := strings.ToLower(url)
	uaLower := strings.ToLower(userAgent)
	
	// Check for known mining pools
	for _, pool := range miningPools {
		if strings.Contains(hostLower, pool) || strings.Contains(urlLower, pool) {
			a.addThreat(Threat{
				Type:     "Cryptocurrency Mining",
				Severity: "high",
				Detail:   fmt.Sprintf("Connection to known mining pool: %s", pool),
				IOC:      host,
			})
			return
		}
	}
	
	// Check for mining keywords in User-Agent or URL
	for _, keyword := range miningKeywords {
		if strings.Contains(uaLower, keyword) || strings.Contains(urlLower, keyword) {
			a.addThreat(Threat{
				Type:     "Cryptocurrency Mining",
				Severity: "high",
				Detail:   fmt.Sprintf("Mining software detected: %s", keyword),
				IOC:      fmt.Sprintf("%s -> %s", info.SrcIP, info.DstIP),
			})
			return
		}
	}
	
	// Check for common mining ports
	for _, port := range miningPorts {
		if info.DstPort == port {
			a.addThreat(Threat{
				Type:     "Suspicious Activity",
				Severity: "medium",
				Detail:   fmt.Sprintf("Connection to common mining port: %d", port),
				IOC:      fmt.Sprintf("%s:%d", info.DstIP, port),
			})
			return
		}
	}
}

func (a *Analyzer) detectStratumProtocol(payload []byte, info PacketInfo) {
	if len(payload) < 20 {
		return
	}
	
	data := string(payload)
	dataLower := strings.ToLower(data)
	
	// Stratum protocol detection
	stratumPatterns := []string{
		`"method":"mining.subscribe"`,
		`"method":"mining.authorize"`,
		`"method":"mining.submit"`,
		`"mining.notify"`,
		`"mining.set_difficulty"`,
		`"mining.set_extranonce"`,
	}
	
	for _, pattern := range stratumPatterns {
		if strings.Contains(dataLower, pattern) {
			a.addThreat(Threat{
				Type:     "Cryptocurrency Mining",
				Severity: "high",
				Detail:   fmt.Sprintf("Stratum mining protocol detected: %s", pattern),
				IOC:      fmt.Sprintf("%s -> %s:%d", info.SrcIP, info.DstIP, info.DstPort),
			})
			return
		}
	}
}
