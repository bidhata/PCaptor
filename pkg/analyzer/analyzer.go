package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Analyzer struct {
	pcapFile   string
	outputDir  string
	workers    int

	// Live capture settings
	iface      string
	bpfFilter  string
	snapLen    int32
	promisc    bool
	stopChan   chan struct{}

	// Results
	packets    []PacketInfo
	flows      map[FlowKey]*Flow
	threats    []Threat
	credentials []Credential
	files      []ExtractedFile
	certs      []Certificate
	ircMessages []IRCMessage
	snmpMessages []SNMPMessage
	ldapMessages []LDAPMessage
	sipMessages []SIPMessage
	xmppMessages []XMPPMessage
	tftpTransfers []TFTPTransfer
	syslogMessages []SyslogMessage
	httpRequests []HTTPRequest
	c2Detections []C2Detection
	tlsFingerprints []TLSFingerprint
	beaconPatterns []BeaconPattern
	sshTunnels []SSHTunnel
	icmpTunnels []ICMPTunnel
	lateralMovements []LateralMovement
	exfiltrations []DataExfiltration
	stegoDetections []StegoDetection
	stats      Statistics

	// Memory management for large files
	maxFlows      int
	maxMessages   int
	flowCount     int
	messageCount  int

	// Synchronization
	mu         sync.RWMutex
	wg         sync.WaitGroup

	// Progress
	totalPackets int64
	processed    int64
	startTime    time.Time
}

type PacketInfo struct {
	Number    int64
	Timestamp time.Time
	Length    int
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Info      string
}

type FlowKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Proto   string
}

type Flow struct {
	Key        FlowKey
	Packets    int64
	Bytes      int64
	StartTime  time.Time
	EndTime    time.Time
	Timestamps []time.Time
}

type Threat struct {
	Type     string
	Severity string
	Detail   string
	IOC      string
	Packet   int64
}

type Credential struct {
	Protocol string
	SrcIP    string
	DstIP    string
	Username string
	Password string
	Method   string
	Strength int
	Packets  []int64
}

type ExtractedFile struct {
	Name     string
	Size     int64
	MD5      string
	Protocol string
	Path     string
}

type Certificate struct {
	Subject  string
	Issuer   string
	NotAfter time.Time
	Path     string
}

type IRCMessage struct {
	Timestamp time.Time
	Channel   string
	Nick      string
	Message   string
	Type      string // JOIN, PART, PRIVMSG, NOTICE, etc.
	SrcIP     string
	DstIP     string
}

type SNMPMessage struct {
	Timestamp   time.Time
	Version     string
	Community   string // v1/v2c community string
	Operation   string // GET, SET, GETNEXT, TRAP, etc.
	OID         string
	Value       string
	SrcIP       string
	DstIP       string
}

type LDAPMessage struct {
	Timestamp time.Time
	Operation string // BIND, SEARCH, ADD, MODIFY, DELETE
	DN        string // Distinguished Name
	Username  string
	Password  string
	Filter    string
	Attributes []string
	SrcIP     string
	DstIP     string
}

type SIPMessage struct {
	Timestamp time.Time
	Method    string // REGISTER, INVITE, BYE, etc.
	From      string
	To        string
	CallID    string
	UserAgent string
	Auth      string
	SrcIP     string
	DstIP     string
}

type XMPPMessage struct {
	Timestamp time.Time
	Type      string // message, presence, iq
	From      string
	To        string
	Body      string
	Subject   string
	SrcIP     string
	DstIP     string
}

type TFTPTransfer struct {
	Timestamp time.Time
	Operation string // RRQ (read) or WRQ (write)
	Filename  string
	Mode      string
	Size      int64
	SrcIP     string
	DstIP     string
}

type SyslogMessage struct {
	Timestamp time.Time
	Facility  int
	Severity  int
	Hostname  string
	Message   string
	SrcIP     string
	DstIP     string
}

type HTTPRequest struct {
	Timestamp  time.Time
	Method     string
	URL        string
	Host       string
	Path       string
	UserAgent  string
	Referer    string
	StatusCode int
	SrcIP      string
	DstIP      string
}

type C2Detection struct {
	Timestamp   time.Time
	Framework   string // CobaltStrike, Metasploit, Empire, etc.
	Indicator   string
	Confidence  string // high, medium, low
	Detail      string
	SrcIP       string
	DstIP       string
	URL         string
}

type Statistics struct {
	TotalPackets   int64
	TotalBytes     int64
	Duration       time.Duration
	Protocols      map[string]int64
	TopTalkers     []TalkerInfo
	ThreatScore    float64
}

type TalkerInfo struct {
	IP      string
	Packets int64
	Bytes   int64
}

func New(pcapFile, outputDir string, workers int) *Analyzer {
	if outputDir == "" {
		base := filepath.Base(pcapFile)
		ext := filepath.Ext(base)
		name := base[:len(base)-len(ext)]
		outputDir = filepath.Join(filepath.Dir(pcapFile), name+"_extracted")
	}

	return &Analyzer{
		pcapFile:    pcapFile,
		outputDir:   outputDir,
		workers:     workers,
		flows:       make(map[FlowKey]*Flow),
		maxFlows:    1000000,
		maxMessages: 100000,
		startTime:   time.Now(),
		stopChan:    make(chan struct{}),
	}
}

func NewLive(iface, bpfFilter, outputDir string, workers int) *Analyzer {
	if outputDir == "" {
		outputDir = fmt.Sprintf("live_%s_%s", iface, time.Now().Format("20060102_150405"))
	}

	return &Analyzer{
		iface:       iface,
		bpfFilter:   bpfFilter,
		outputDir:   outputDir,
		workers:     workers,
		snapLen:     65535,
		promisc:     true,
		flows:       make(map[FlowKey]*Flow),
		maxFlows:    1000000,
		maxMessages: 100000,
		startTime:   time.Now(),
		stopChan:    make(chan struct{}),
	}
}

func (a *Analyzer) Analyze() error {
	// Open PCAP file
	handle, err := pcap.OpenOffline(a.pcapFile)
	if err != nil {
		return fmt.Errorf("failed to open PCAP: %w", err)
	}
	defer handle.Close()

	// Create output directory
	if err := os.MkdirAll(a.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	os.MkdirAll(filepath.Join(a.outputDir, "files"), 0755)
	os.MkdirAll(filepath.Join(a.outputDir, "certificates"), 0755)

	fmt.Println("Processing packets...")

	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	// Create worker pool with larger buffer for better throughput
	workChan := make(chan gopacket.Packet, a.workers*100)
	
	// Start workers
	for i := 0; i < a.workers; i++ {
		a.wg.Add(1)
		go a.worker(workChan)
	}

	// Progress reporter
	done := make(chan bool)
	go a.progressReporter(done)

	// Feed packets to workers (non-blocking with larger buffer)
	packetNum := int64(0)
	for packet := range packetChan {
		packetNum++
		workChan <- packet
		
		// Update total packets estimate less frequently
		if packetNum%50000 == 0 {
			a.mu.Lock()
			a.totalPackets = packetNum
			a.mu.Unlock()
		}
	}
	close(workChan)

	// Wait for workers to finish
	a.wg.Wait()
	done <- true

	// Final packet count
	a.mu.Lock()
	a.totalPackets = packetNum
	a.mu.Unlock()

	fmt.Printf("\nProcessed %d packets\n", packetNum)

	// Post-processing
	fmt.Println("Detecting anomalies...")
	a.detectAnomalies()
	
	// Advanced threat detection
	fmt.Println("Running advanced threat detection...")
	
	// Beaconing detection
	beacons := a.detectBeaconing()
	a.beaconPatterns = beacons
	a.addBeaconThreats(beacons)
	
	// SSH tunneling detection
	sshTunnels := a.detectSSHTunneling()
	a.sshTunnels = sshTunnels
	a.addSSHTunnelThreats(sshTunnels)
	
	// Lateral movement detection
	lateralMovements := a.detectLateralMovement()
	a.lateralMovements = lateralMovements
	a.addLateralMovementThreats(lateralMovements)
	
	// Data exfiltration detection
	exfiltrations := a.detectExfiltration()
	a.exfiltrations = exfiltrations
	a.addExfiltrationThreats(exfiltrations)

	a.calculateStatistics()

	return nil
}

func (a *Analyzer) AnalyzeLive() error {
	handle, err := pcap.OpenLive(a.iface, a.snapLen, a.promisc, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", a.iface, err)
	}
	defer handle.Close()

	if a.bpfFilter != "" {
		if err := handle.SetBPFFilter(a.bpfFilter); err != nil {
			return fmt.Errorf("invalid BPF filter %q: %w", a.bpfFilter, err)
		}
	}

	if err := os.MkdirAll(a.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	os.MkdirAll(filepath.Join(a.outputDir, "files"), 0755)
	os.MkdirAll(filepath.Join(a.outputDir, "certificates"), 0755)

	fmt.Printf("Capturing on interface %s ...\n", a.iface)
	if a.bpfFilter != "" {
		fmt.Printf("BPF filter: %s\n", a.bpfFilter)
	}
	fmt.Println("Press Ctrl+C to stop capture and generate reports.")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	workChan := make(chan gopacket.Packet, a.workers*100)

	for i := 0; i < a.workers; i++ {
		a.wg.Add(1)
		go a.worker(workChan)
	}

	done := make(chan bool)
	go a.progressReporter(done)

	packetNum := int64(0)
loop:
	for {
		select {
		case <-a.stopChan:
			break loop
		case packet, ok := <-packetChan:
			if !ok {
				break loop
			}
			packetNum++
			workChan <- packet

			if packetNum%50000 == 0 {
				a.mu.Lock()
				a.totalPackets = packetNum
				a.mu.Unlock()
			}
		}
	}
	close(workChan)

	a.wg.Wait()
	done <- true

	a.mu.Lock()
	a.totalPackets = packetNum
	a.mu.Unlock()

	fmt.Printf("\nCaptured and processed %d packets\n", packetNum)

	if packetNum == 0 {
		fmt.Println("No packets captured.")
		return nil
	}

	fmt.Println("Detecting anomalies...")
	a.detectAnomalies()

	fmt.Println("Running advanced threat detection...")

	beacons := a.detectBeaconing()
	a.beaconPatterns = beacons
	a.addBeaconThreats(beacons)

	sshTunnels := a.detectSSHTunneling()
	a.sshTunnels = sshTunnels
	a.addSSHTunnelThreats(sshTunnels)

	lateralMovements := a.detectLateralMovement()
	a.lateralMovements = lateralMovements
	a.addLateralMovementThreats(lateralMovements)

	exfiltrations := a.detectExfiltration()
	a.exfiltrations = exfiltrations
	a.addExfiltrationThreats(exfiltrations)

	a.calculateStatistics()

	return nil
}

func (a *Analyzer) StopCapture() {
	select {
	case <-a.stopChan:
		// Already closed
	default:
		close(a.stopChan)
	}
}

func (a *Analyzer) countPackets() int64 {
	handle, err := pcap.OpenOffline(a.pcapFile)
	if err != nil {
		return 0
	}
	defer handle.Close()

	count := int64(0)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for range packetSource.Packets() {
		count++
	}
	return count
}

func (a *Analyzer) progressReporter(done chan bool) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			a.mu.RLock()
			processed := a.processed
			total := a.totalPackets
			a.mu.RUnlock()

			elapsed := time.Since(a.startTime)
			rate := float64(processed) / elapsed.Seconds()
			
			if total > 0 {
				pct := float64(processed) / float64(total) * 100
				fmt.Printf("\rProcessed: %d/%d (%.1f%%) - %.0f pkt/s", 
					processed, total, pct, rate)
			} else {
				fmt.Printf("\rProcessed: %d packets - %.0f pkt/s", processed, rate)
			}
		}
	}
}

func (a *Analyzer) PrintSummary() {
	fmt.Println("\n\n=== Analysis Summary ===")
	fmt.Printf("Total Packets: %d\n", a.stats.TotalPackets)
	fmt.Printf("Total Bytes: %d\n", a.stats.TotalBytes)
	fmt.Printf("Duration: %v\n", a.stats.Duration)
	fmt.Printf("Flows: %d\n", len(a.flows))
	fmt.Printf("Threats: %d\n", len(a.threats))
	fmt.Printf("Credentials: %d\n", len(a.credentials))
	fmt.Printf("Extracted Files: %d\n", len(a.files))
	fmt.Printf("Certificates: %d\n", len(a.certs))
	fmt.Printf("HTTP Requests: %d\n", len(a.httpRequests))
	fmt.Printf("C2 Detections: %d\n", len(a.c2Detections))
	fmt.Printf("IRC Messages: %d\n", len(a.ircMessages))
	fmt.Printf("SNMP Messages: %d\n", len(a.snmpMessages))
	fmt.Printf("LDAP Messages: %d\n", len(a.ldapMessages))
	fmt.Printf("SIP Messages: %d\n", len(a.sipMessages))
	fmt.Printf("XMPP Messages: %d\n", len(a.xmppMessages))
	fmt.Printf("TFTP Transfers: %d\n", len(a.tftpTransfers))
	fmt.Printf("Syslog Messages: %d\n", len(a.syslogMessages))
	fmt.Printf("Threat Score: %.1f/100\n", a.stats.ThreatScore)
	fmt.Printf("\nProcessing Time: %v\n", time.Since(a.startTime))
	fmt.Printf("Output Directory: %s\n", a.outputDir)
}


// Helper methods for GUI
func (a *Analyzer) GetStats() Statistics {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.stats
}

func (a *Analyzer) GetFlowCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.flows)
}

func (a *Analyzer) GetThreatCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.threats)
}

func (a *Analyzer) GetCredentialCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.credentials)
}

func (a *Analyzer) GetFileCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.files)
}

func (a *Analyzer) GetCertCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.certs)
}

func (a *Analyzer) GetThreats() []Threat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]Threat{}, a.threats...)
}

func (a *Analyzer) GetCredentials() []Credential {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return append([]Credential{}, a.credentials...)
}

func (a *Analyzer) GetTopFlows(limit int) []Flow {
	a.mu.RLock()
	defer a.mu.RUnlock()
	
	// For large flow counts, use a min-heap approach to avoid sorting everything
	if len(a.flows) > 10000 {
		// Keep only top N flows using a simple selection algorithm
		topFlows := make([]Flow, 0, limit)
		minBytes := int64(0)
		
		for _, flow := range a.flows {
			if len(topFlows) < limit {
				topFlows = append(topFlows, *flow)
				if flow.Bytes < minBytes || minBytes == 0 {
					minBytes = flow.Bytes
				}
			} else if flow.Bytes > minBytes {
				// Replace smallest flow
				minIdx := 0
				minBytes = topFlows[0].Bytes
				for i := 1; i < len(topFlows); i++ {
					if topFlows[i].Bytes < minBytes {
						minBytes = topFlows[i].Bytes
						minIdx = i
					}
				}
				topFlows[minIdx] = *flow
			}
		}
		
		// Simple bubble sort for small array
		for i := 0; i < len(topFlows)-1; i++ {
			for j := i + 1; j < len(topFlows); j++ {
				if topFlows[j].Bytes > topFlows[i].Bytes {
					topFlows[i], topFlows[j] = topFlows[j], topFlows[i]
				}
			}
		}
		
		return topFlows
	}
	
	// For smaller flow counts, use original approach
	flows := make([]Flow, 0, len(a.flows))
	for _, flow := range a.flows {
		flows = append(flows, *flow)
	}
	
	// Sort by bytes
	for i := 0; i < len(flows)-1; i++ {
		for j := i + 1; j < len(flows); j++ {
			if flows[j].Bytes > flows[i].Bytes {
				flows[i], flows[j] = flows[j], flows[i]
			}
		}
	}
	
	if len(flows) > limit {
		flows = flows[:limit]
	}
	
	return flows
}

func (a *Analyzer) GetOutputDir() string {
	return a.outputDir
}

func (a *Analyzer) GetProcessingTime() time.Duration {
	return time.Since(a.startTime)
}

// Dashboard getters — thread-safe read access for live streaming

func (a *Analyzer) GetProcessed() int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.processed
}

func (a *Analyzer) GetTotalBytes() int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var total int64
	for _, flow := range a.flows {
		total += flow.Bytes
	}
	return total
}

func (a *Analyzer) GetProtocolDistribution() map[string]int64 {
	a.mu.RLock()
	defer a.mu.RUnlock()
	dist := make(map[string]int64)
	for key, flow := range a.flows {
		dist[key.Proto] += flow.Packets
	}
	return dist
}

func (a *Analyzer) GetTopTalkers(limit int) []TalkerInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()
	talkers := make(map[string]*TalkerInfo)
	for key, flow := range a.flows {
		if _, ok := talkers[key.SrcIP]; !ok {
			talkers[key.SrcIP] = &TalkerInfo{IP: key.SrcIP}
		}
		talkers[key.SrcIP].Packets += flow.Packets
		talkers[key.SrcIP].Bytes += flow.Bytes
	}
	result := make([]TalkerInfo, 0, len(talkers))
	for _, t := range talkers {
		result = append(result, *t)
	}
	// Simple sort by bytes descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Bytes > result[i].Bytes {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	if len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (a *Analyzer) GetRecentThreats(limit int) []Threat {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := len(a.threats)
	if n == 0 {
		return nil
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	return append([]Threat{}, a.threats[start:]...)
}

func (a *Analyzer) GetRecentC2(limit int) []C2Detection {
	a.mu.RLock()
	defer a.mu.RUnlock()
	n := len(a.c2Detections)
	if n == 0 {
		return nil
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	return append([]C2Detection{}, a.c2Detections[start:]...)
}

func (a *Analyzer) GetHTTPRequestCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.httpRequests)
}

func (a *Analyzer) GetC2DetectionCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.c2Detections)
}

func (a *Analyzer) GetStartTime() time.Time {
	return a.startTime
}

func (a *Analyzer) IsCaptureStopped() bool {
	select {
	case <-a.stopChan:
		return true
	default:
		return false
	}
}
