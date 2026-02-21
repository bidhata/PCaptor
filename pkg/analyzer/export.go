package analyzer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (a *Analyzer) ExportHTML() error {
	fmt.Println("Generating HTML report...")
	
	outputFile := filepath.Join(filepath.Dir(a.pcapFile), 
		strings.TrimSuffix(filepath.Base(a.pcapFile), filepath.Ext(a.pcapFile))+"_report.html")

	fmt.Println("  - Building HTML content...")
	html := a.generateHTML()
	
	fmt.Println("  - Writing to file...")
	if err := os.WriteFile(outputFile, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML: %w", err)
	}

	fmt.Printf("HTML report saved: %s\n", outputFile)
	return nil
}

func (a *Analyzer) ExportJSON() error {
	outputFile := filepath.Join(filepath.Dir(a.pcapFile), 
		strings.TrimSuffix(filepath.Base(a.pcapFile), filepath.Ext(a.pcapFile))+"_report.json")

	// Convert flows map to slice for JSON marshaling
	flowsList := make([]map[string]interface{}, 0, len(a.flows))
	for key, flow := range a.flows {
		flowsList = append(flowsList, map[string]interface{}{
			"src_ip":   key.SrcIP,
			"src_port": key.SrcPort,
			"dst_ip":   key.DstIP,
			"dst_port": key.DstPort,
			"protocol": key.Proto,
			"packets":  flow.Packets,
			"bytes":    flow.Bytes,
			"start":    flow.StartTime,
			"end":      flow.EndTime,
		})
	}

	data := map[string]interface{}{
		"statistics":        a.stats,
		"flows":             flowsList,
		"threats":           a.threats,
		"credentials":       a.credentials,
		"files":             a.files,
		"certificates":      a.certs,
		"http_requests":     a.httpRequests,
		"c2_detections":     a.c2Detections,
		"tls_fingerprints":  a.tlsFingerprints,
		"beacon_patterns":   a.beaconPatterns,
		"ssh_tunnels":       a.sshTunnels,
		"icmp_tunnels":      a.icmpTunnels,
		"lateral_movements": a.lateralMovements,
		"exfiltrations":     a.exfiltrations,
		"stego_detections":  a.stegoDetections,
		"irc_messages":      a.ircMessages,
		"snmp_messages":     a.snmpMessages,
		"ldap_messages":     a.ldapMessages,
		"sip_messages":      a.sipMessages,
		"xmpp_messages":     a.xmppMessages,
		"tftp_transfers":    a.tftpTransfers,
		"syslog_messages":   a.syslogMessages,
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON: %w", err)
	}

	fmt.Printf("JSON report saved: %s\n", outputFile)
	return nil
}

func (a *Analyzer) ExportCSV() error {
	baseFile := filepath.Join(filepath.Dir(a.pcapFile), 
		strings.TrimSuffix(filepath.Base(a.pcapFile), filepath.Ext(a.pcapFile)))

	// Export threats
	if err := a.exportThreatsCSV(baseFile + "_threats.csv"); err != nil {
		return err
	}

	// Export credentials
	if err := a.exportCredentialsCSV(baseFile + "_credentials.csv"); err != nil {
		return err
	}

	// Export IRC messages
	if len(a.ircMessages) > 0 {
		if err := a.exportIRCMessagesCSV(baseFile + "_irc_chat.csv"); err != nil {
			return err
		}
	}

	// Export SNMP messages
	if len(a.snmpMessages) > 0 {
		if err := a.exportSNMPMessagesCSV(baseFile + "_snmp.csv"); err != nil {
			return err
		}
	}

	// Export LDAP messages
	if len(a.ldapMessages) > 0 {
		if err := a.exportLDAPMessagesCSV(baseFile + "_ldap.csv"); err != nil {
			return err
		}
	}

	// Export SIP messages
	if len(a.sipMessages) > 0 {
		if err := a.exportSIPMessagesCSV(baseFile + "_sip.csv"); err != nil {
			return err
		}
	}

	// Export XMPP messages
	if len(a.xmppMessages) > 0 {
		if err := a.exportXMPPMessagesCSV(baseFile + "_xmpp.csv"); err != nil {
			return err
		}
	}

	// Export TFTP transfers
	if len(a.tftpTransfers) > 0 {
		if err := a.exportTFTPTransfersCSV(baseFile + "_tftp.csv"); err != nil {
			return err
		}
	}

	// Export Syslog messages
	if len(a.syslogMessages) > 0 {
		if err := a.exportSyslogMessagesCSV(baseFile + "_syslog.csv"); err != nil {
			return err
		}
	}

	// Export HTTP requests
	if len(a.httpRequests) > 0 {
		if err := a.exportHTTPRequestsCSV(baseFile + "_http_urls.csv"); err != nil {
			return err
		}
	}

	// Export C2 detections
	if len(a.c2Detections) > 0 {
		if err := a.exportC2DetectionsCSV(baseFile + "_c2_detections.csv"); err != nil {
			return err
		}
	}
	
	// Export beacon patterns
	if len(a.beaconPatterns) > 0 {
		if err := a.exportBeaconPatternsCSV(baseFile + "_beaconing.csv"); err != nil {
			return err
		}
	}
	
	// Export SSH tunnels
	if len(a.sshTunnels) > 0 {
		if err := a.exportSSHTunnelsCSV(baseFile + "_ssh_tunnels.csv"); err != nil {
			return err
		}
	}
	
	// Export lateral movements
	if len(a.lateralMovements) > 0 {
		if err := a.exportLateralMovementsCSV(baseFile + "_lateral_movement.csv"); err != nil {
			return err
		}
	}
	
	// Export exfiltrations
	if len(a.exfiltrations) > 0 {
		if err := a.exportExfiltrationsCSV(baseFile + "_exfiltration.csv"); err != nil {
			return err
		}
	}
	
	// Export TLS fingerprints
	if len(a.tlsFingerprints) > 0 {
		if err := a.exportTLSFingerprintsCSV(baseFile + "_tls_fingerprints.csv"); err != nil {
			return err
		}
	}

	fmt.Printf("CSV reports saved: %s_*.csv\n", baseFile)
	return nil
}

func (a *Analyzer) exportThreatsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Type", "Severity", "Detail", "IOC", "Packet"})

	// Data
	for _, threat := range a.threats {
		writer.Write([]string{
			threat.Type,
			threat.Severity,
			threat.Detail,
			threat.IOC,
			fmt.Sprintf("%d", threat.Packet),
		})
	}

	return nil
}

func (a *Analyzer) exportCredentialsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Protocol", "Source IP", "Destination IP", "Username", "Password", "Method", "Strength"})

	// Data
	for _, cred := range a.credentials {
		writer.Write([]string{
			cred.Protocol,
			cred.SrcIP,
			cred.DstIP,
			cred.Username,
			cred.Password,
			cred.Method,
			fmt.Sprintf("%d", cred.Strength),
		})
	}

	return nil
}

func (a *Analyzer) exportIRCMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header
	writer.Write([]string{"Timestamp", "Channel", "Nick", "Type", "Message", "Source IP", "Destination IP"})

	// Data
	for _, msg := range a.ircMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.Channel,
			msg.Nick,
			msg.Type,
			msg.Message,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) generateHTML() string {
	fmt.Println("    - Generating summary...")
	summaryHTML := a.generateSummaryHTML()
	
	fmt.Println("    - Generating threats table...")
	threatsHTML := a.generateThreatsHTML()
	
	fmt.Println("    - Generating C2 detections...")
	c2HTML := a.generateC2HTML()
	
	fmt.Println("    - Generating URLs table...")
	urlsHTML := a.generateURLsHTML()
	
	fmt.Println("    - Generating credentials table...")
	credentialsHTML := a.generateCredentialsHTML()
	
	fmt.Println("    - Generating IRC chat log...")
	ircHTML := a.generateIRCHTML()
	
	fmt.Println("    - Generating SNMP table...")
	snmpHTML := a.generateSNMPHTML()
	
	fmt.Println("    - Generating LDAP table...")
	ldapHTML := a.generateLDAPHTML()
	
	fmt.Println("    - Generating SIP table...")
	sipHTML := a.generateSIPHTML()
	
	fmt.Println("    - Generating XMPP table...")
	xmppHTML := a.generateXMPPHTML()
	
	fmt.Println("    - Generating TFTP table...")
	tftpHTML := a.generateTFTPHTML()
	
	fmt.Println("    - Generating Syslog table...")
	syslogHTML := a.generateSyslogHTML()
	
	fmt.Println("    - Generating beaconing patterns...")
	beaconingHTML := a.generateBeaconingHTML()
	
	fmt.Println("    - Generating SSH tunnels...")
	sshTunnelsHTML := a.generateSSHTunnelsHTML()
	
	fmt.Println("    - Generating ICMP tunnels...")
	icmpTunnelsHTML := a.generateICMPTunnelsHTML()
	
	fmt.Println("    - Generating lateral movement...")
	lateralMovementHTML := a.generateLateralMovementHTML()
	
	fmt.Println("    - Generating exfiltration...")
	exfiltrationHTML := a.generateExfiltrationHTML()
	
	fmt.Println("    - Generating TLS fingerprints...")
	tlsFingerprintsHTML := a.generateTLSFingerprintsHTML()
	
	fmt.Println("    - Generating steganography detections...")
	stegoHTML := a.generateStegoHTML()
	
	fmt.Println("    - Generating flows table...")
	flowsHTML := a.generateFlowsHTML()
	
	fmt.Println("    - Assembling final HTML...")
	// Replace template placeholders
	html := htmlTemplate
	html = strings.ReplaceAll(html, "{{.FileName}}", filepath.Base(a.pcapFile))
	html = strings.ReplaceAll(html, "{{.GeneratedTime}}", time.Now().Format("January 2, 2006 at 3:04 PM"))
	html = strings.ReplaceAll(html, "{{.TotalPackets}}", a.formatNumber(a.stats.TotalPackets))
	html = strings.ReplaceAll(html, "{{.TotalFlows}}", fmt.Sprintf("%d", len(a.flows)))
	html = strings.ReplaceAll(html, "{{.TotalThreats}}", fmt.Sprintf("%d", len(a.threats)))
	html = strings.ReplaceAll(html, "{{.TotalCredentials}}", fmt.Sprintf("%d", len(a.credentials)))
	html = strings.ReplaceAll(html, "{{.TotalIRCMessages}}", fmt.Sprintf("%d", len(a.ircMessages)))
	html = strings.ReplaceAll(html, "{{.ThreatScore}}", fmt.Sprintf("%.0f", a.stats.ThreatScore))
	html = strings.ReplaceAll(html, "{{.SummaryHTML}}", summaryHTML)
	html = strings.ReplaceAll(html, "{{.ThreatsHTML}}", threatsHTML)
	html = strings.ReplaceAll(html, "{{.C2HTML}}", c2HTML)
	html = strings.ReplaceAll(html, "{{.URLsHTML}}", urlsHTML)
	html = strings.ReplaceAll(html, "{{.CredentialsHTML}}", credentialsHTML)
	html = strings.ReplaceAll(html, "{{.IRCHTML}}", ircHTML)
	html = strings.ReplaceAll(html, "{{.SNMPHTML}}", snmpHTML)
	html = strings.ReplaceAll(html, "{{.LDAPHTML}}", ldapHTML)
	html = strings.ReplaceAll(html, "{{.SIPHTML}}", sipHTML)
	html = strings.ReplaceAll(html, "{{.XMPPHTML}}", xmppHTML)
	html = strings.ReplaceAll(html, "{{.TFTPHTML}}", tftpHTML)
	html = strings.ReplaceAll(html, "{{.SyslogHTML}}", syslogHTML)
	html = strings.ReplaceAll(html, "{{.BeaconingHTML}}", beaconingHTML)
	html = strings.ReplaceAll(html, "{{.SSHTunnelsHTML}}", sshTunnelsHTML)
	html = strings.ReplaceAll(html, "{{.ICMPTunnelsHTML}}", icmpTunnelsHTML)
	html = strings.ReplaceAll(html, "{{.LateralMovementHTML}}", lateralMovementHTML)
	html = strings.ReplaceAll(html, "{{.ExfiltrationHTML}}", exfiltrationHTML)
	html = strings.ReplaceAll(html, "{{.TLSFingerprintsHTML}}", tlsFingerprintsHTML)
	html = strings.ReplaceAll(html, "{{.StegoHTML}}", stegoHTML)
	html = strings.ReplaceAll(html, "{{.FlowsHTML}}", flowsHTML)
	
	return html
}

func (a *Analyzer) formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}

func (a *Analyzer) generateThreatsHTML() string {
	if len(a.threats) == 0 {
		return `<div class="empty-state">
            <div class="empty-state-icon">✅</div>
            <div class="empty-state-text">No security threats detected</div>
        </div>`
	}

	html := `<div class="table-container"><table id="threats-table">
        <thead>
            <tr>
                <th onclick="sortTable('threats-table', 0)">Type</th>
                <th onclick="sortTable('threats-table', 1)">Severity</th>
                <th onclick="sortTable('threats-table', 2)">Details</th>
                <th onclick="sortTable('threats-table', 3)">Indicator of Compromise</th>
            </tr>
        </thead>
        <tbody>`

	for _, threat := range a.threats {
		badgeClass := "badge-low"
		icon := "✓"
		if threat.Severity == "high" {
			badgeClass = "badge-high"
			icon = "⚠"
		} else if threat.Severity == "medium" {
			badgeClass = "badge-medium"
			icon = "⚡"
		}

		html += fmt.Sprintf(`
            <tr>
                <td><strong>%s</strong></td>
                <td><span class="badge %s"><span>%s</span> %s</span></td>
                <td>%s</td>
                <td><span class="code">%s</span></td>
            </tr>`,
			threat.Type,
			badgeClass,
			icon,
			strings.ToUpper(threat.Severity),
			threat.Detail,
			threat.IOC,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateCredentialsHTML() string {
	if len(a.credentials) == 0 {
		return `<div class="empty-state">
            <div class="empty-state-icon">✅</div>
            <div class="empty-state-text">No credentials found in cleartext</div>
        </div>`
	}

	html := `<div class="table-container"><table id="credentials-table">
        <thead>
            <tr>
                <th onclick="sortTable('credentials-table', 0)">Protocol</th>
                <th onclick="sortTable('credentials-table', 1)">Connection</th>
                <th onclick="sortTable('credentials-table', 2)">Username</th>
                <th onclick="sortTable('credentials-table', 3)">Password</th>
                <th onclick="sortTable('credentials-table', 4)">Strength</th>
            </tr>
        </thead>
        <tbody>`

	for _, cred := range a.credentials {
		strengthClass := "strength-weak"
		strengthLabel := "Weak"
		if cred.Strength >= 70 {
			strengthClass = "strength-strong"
			strengthLabel = "Strong"
		} else if cred.Strength >= 50 {
			strengthClass = "strength-good"
			strengthLabel = "Good"
		} else if cred.Strength >= 30 {
			strengthClass = "strength-fair"
			strengthLabel = "Fair"
		}

		html += fmt.Sprintf(`
            <tr>
                <td><span class="badge badge-protocol">%s</span></td>
                <td><span class="code">%s → %s</span></td>
                <td><strong>%s</strong></td>
                <td><span class="code">%s</span></td>
                <td>
                    <div class="strength-container">
                        <div class="strength-label">
                            <span>%s</span>
                            <span>%d/100</span>
                        </div>
                        <div class="strength-bar">
                            <div class="strength-fill %s" style="width: %d%%"></div>
                        </div>
                    </div>
                </td>
            </tr>`,
			cred.Protocol,
			cred.SrcIP,
			cred.DstIP,
			cred.Username,
			cred.Password,
			strengthLabel,
			cred.Strength,
			strengthClass,
			cred.Strength,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateSummaryHTML() string {
	fmt.Println("      - Counting unique IPs...")
	uniqueIPs := a.countUniqueIPs()
	
	fmt.Println("      - Building summary HTML...")
	html := `<div class="summary-grid">
        <div class="summary-card">
            <h3>📦 Packet Statistics</h3>
            <div class="summary-item">
                <span class="summary-label">Total Packets</span>
                <span class="summary-value">` + a.formatNumber(a.stats.TotalPackets) + `</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Total Bytes</span>
                <span class="summary-value">` + a.formatBytes(a.stats.TotalBytes) + `</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Duration</span>
                <span class="summary-value">` + a.stats.Duration.String() + `</span>
            </div>
        </div>
        
        <div class="summary-card">
            <h3>🌐 Network Activity</h3>
            <div class="summary-item">
                <span class="summary-label">Total Flows</span>
                <span class="summary-value">` + fmt.Sprintf("%d", len(a.flows)) + `</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Unique IPs</span>
                <span class="summary-value">` + fmt.Sprintf("%d", uniqueIPs) + `</span>
            </div>
        </div>
        
        <div class="summary-card">
            <h3>🔒 Security Analysis</h3>
            <div class="summary-item">
                <span class="summary-label">Threats Detected</span>
                <span class="summary-value">` + fmt.Sprintf("%d", len(a.threats)) + `</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Credentials Found</span>
                <span class="summary-value">` + fmt.Sprintf("%d", len(a.credentials)) + `</span>
            </div>
            <div class="summary-item">
                <span class="summary-label">Threat Score</span>
                <span class="summary-value">` + fmt.Sprintf("%.0f/100", a.stats.ThreatScore) + `</span>
            </div>
        </div>
    </div>`
	
	return html
}

func (a *Analyzer) generateFlowsHTML() string {
	fmt.Println("      - Getting top flows...")
	// Limit to 50 flows for performance
	flows := a.GetTopFlows(50)
	
	fmt.Println("      - Building flows table...")
	if len(flows) == 0 {
		return `<div class="empty-state">
            <div class="empty-state-icon">📭</div>
            <div class="empty-state-text">No network flows found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="flows-table">
        <thead>
            <tr>
                <th onclick="sortTable('flows-table', 0)">Source</th>
                <th onclick="sortTable('flows-table', 1)">Destination</th>
                <th onclick="sortTable('flows-table', 2)">Protocol</th>
                <th onclick="sortTable('flows-table', 3)">Packets</th>
                <th onclick="sortTable('flows-table', 4)">Bytes</th>
                <th onclick="sortTable('flows-table', 5)">Duration</th>
            </tr>
        </thead>
        <tbody>`

	for _, flow := range flows {
		duration := flow.EndTime.Sub(flow.StartTime)
		
		html += fmt.Sprintf(`
            <tr>
                <td><span class="code">%s:%d</span></td>
                <td><span class="code">%s:%d</span></td>
                <td><span class="badge badge-protocol">%s</span></td>
                <td>%s</td>
                <td>%s</td>
                <td>%v</td>
            </tr>`,
			flow.Key.SrcIP,
			flow.Key.SrcPort,
			flow.Key.DstIP,
			flow.Key.DstPort,
			flow.Key.Proto,
			a.formatNumber(flow.Packets),
			a.formatBytes(flow.Bytes),
			duration.Round(time.Millisecond),
		)
	}

	html += fmt.Sprintf(`</tbody></table></div>
	<p style="text-align: center; color: #718096; margin-top: 1rem; font-size: 0.875rem;">
		Showing top 50 flows out of %d total flows
	</p>`, len(a.flows))
	
	return html
}

func (a *Analyzer) countUniqueIPs() int {
	ips := make(map[string]bool)
	count := 0
	maxFlows := 10000 // Limit iteration to prevent hang on large captures
	
	for key := range a.flows {
		if count >= maxFlows {
			break
		}
		ips[key.SrcIP] = true
		ips[key.DstIP] = true
		count++
	}
	
	// If we hit the limit, estimate based on sample
	if count >= maxFlows {
		ratio := float64(len(a.flows)) / float64(maxFlows)
		return int(float64(len(ips)) * ratio)
	}
	
	return len(ips)
}

func (a *Analyzer) formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}


func (a *Analyzer) generateIRCHTML() string {
	if len(a.ircMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-state-icon">💬</div>
            <div class="empty-state-text">No IRC chat messages found</div>
        </div>`
	}

	// Group messages by channel
	channels := make(map[string][]IRCMessage)
	for _, msg := range a.ircMessages {
		channels[msg.Channel] = append(channels[msg.Channel], msg)
	}

	html := `<div class="irc-container">`
	
	// Create channel tabs if multiple channels
	if len(channels) > 1 {
		html += `<div class="irc-channels">`
		first := true
		for channel := range channels {
			activeClass := ""
			if first {
				activeClass = " active"
				first = false
			}
			html += fmt.Sprintf(`<button class="irc-channel-btn%s" onclick="showIRCChannel('%s')">%s (%d)</button>`,
				activeClass, channel, channel, len(channels[channel]))
		}
		html += `</div>`
	}

	// Create message lists for each channel
	first := true
	for channel, messages := range channels {
		displayStyle := "none"
		if first {
			displayStyle = "block"
			first = false
		}
		
		html += fmt.Sprintf(`<div class="irc-channel" id="irc-%s" style="display: %s;">`, channel, displayStyle)
		html += `<div class="irc-messages">`
		
		for _, msg := range messages {
			typeClass := "irc-msg-" + strings.ToLower(msg.Type)
			timestamp := msg.Timestamp.Format("15:04:05")
			
			switch msg.Type {
			case "PRIVMSG", "NOTICE":
				html += fmt.Sprintf(`
					<div class="irc-message %s">
						<span class="irc-time">%s</span>
						<span class="irc-nick">%s</span>
						<span class="irc-text">%s</span>
					</div>`,
					typeClass, timestamp, msg.Nick, msg.Message)
			default:
				html += fmt.Sprintf(`
					<div class="irc-message %s">
						<span class="irc-time">%s</span>
						<span class="irc-system">%s</span>
					</div>`,
					typeClass, timestamp, msg.Message)
			}
		}
		
		html += `</div></div>`
	}
	
	html += `</div>`
	
	// Add JavaScript for channel switching
	html += `
	<script>
	function showIRCChannel(channel) {
		// Hide all channels
		document.querySelectorAll('.irc-channel').forEach(el => el.style.display = 'none');
		// Show selected channel
		document.getElementById('irc-' + channel).style.display = 'block';
		// Update button states
		document.querySelectorAll('.irc-channel-btn').forEach(btn => btn.classList.remove('active'));
		event.target.classList.add('active');
	}
	</script>`
	
	return html
}


func (a *Analyzer) exportSNMPMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Version", "Community", "Operation", "OID", "Value", "Source IP", "Destination IP"})

	for _, msg := range a.snmpMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.Version,
			msg.Community,
			msg.Operation,
			msg.OID,
			msg.Value,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportLDAPMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Operation", "DN", "Username", "Password", "Filter", "Source IP", "Destination IP"})

	for _, msg := range a.ldapMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.Operation,
			msg.DN,
			msg.Username,
			msg.Password,
			msg.Filter,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportSIPMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Method", "From", "To", "Call-ID", "User-Agent", "Auth", "Source IP", "Destination IP"})

	for _, msg := range a.sipMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.Method,
			msg.From,
			msg.To,
			msg.CallID,
			msg.UserAgent,
			msg.Auth,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportXMPPMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Type", "From", "To", "Subject", "Body", "Source IP", "Destination IP"})

	for _, msg := range a.xmppMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			msg.Type,
			msg.From,
			msg.To,
			msg.Subject,
			msg.Body,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportTFTPTransfersCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Operation", "Filename", "Mode", "Size", "Source IP", "Destination IP"})

	for _, transfer := range a.tftpTransfers {
		writer.Write([]string{
			transfer.Timestamp.Format("2006-01-02 15:04:05"),
			transfer.Operation,
			transfer.Filename,
			transfer.Mode,
			fmt.Sprintf("%d", transfer.Size),
			transfer.SrcIP,
			transfer.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportSyslogMessagesCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Facility", "Severity", "Hostname", "Message", "Source IP", "Destination IP"})

	for _, msg := range a.syslogMessages {
		writer.Write([]string{
			msg.Timestamp.Format("2006-01-02 15:04:05"),
			fmt.Sprintf("%d", msg.Facility),
			fmt.Sprintf("%d", msg.Severity),
			msg.Hostname,
			msg.Message,
			msg.SrcIP,
			msg.DstIP,
		})
	}

	return nil
}


func (a *Analyzer) exportHTTPRequestsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Method", "URL", "Host", "Path", "User-Agent", "Referer", "Source IP", "Destination IP"})

	for _, req := range a.httpRequests {
		writer.Write([]string{
			req.Timestamp.Format("2006-01-02 15:04:05"),
			req.Method,
			req.URL,
			req.Host,
			req.Path,
			req.UserAgent,
			req.Referer,
			req.SrcIP,
			req.DstIP,
		})
	}

	return nil
}

func (a *Analyzer) exportC2DetectionsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Framework", "Indicator", "Confidence", "Detail", "URL", "Source IP", "Destination IP"})

	for _, detection := range a.c2Detections {
		writer.Write([]string{
			detection.Timestamp.Format("2006-01-02 15:04:05"),
			detection.Framework,
			detection.Indicator,
			detection.Confidence,
			detection.Detail,
			detection.URL,
			detection.SrcIP,
			detection.DstIP,
		})
	}

	return nil
}


func (a *Analyzer) generateC2HTML() string {
	if len(a.c2Detections) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">✅</div>
            <div>No C2 communications detected</div>
        </div>`
	}

	html := `<div class="table-container"><table id="c2-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Framework</th>
                <th>Confidence</th>
                <th>Indicator</th>
                <th>URL</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, c2 := range a.c2Detections {
		confidenceClass := "badge-info"
		if c2.Confidence == "high" {
			confidenceClass = "badge-danger"
		} else if c2.Confidence == "medium" {
			confidenceClass = "badge-warning"
		}

		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><strong>%s</strong></td>
                <td><span class="badge %s">%s</span></td>
                <td>%s</td>
                <td><span class="code">%s</span></td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			c2.Timestamp.Format("15:04:05"),
			c2.Framework,
			confidenceClass,
			strings.ToUpper(c2.Confidence),
			c2.Indicator,
			c2.URL,
			c2.SrcIP,
			c2.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateURLsHTML() string {
	if len(a.httpRequests) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">🔗</div>
            <div>No HTTP URLs found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="urls-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Method</th>
                <th>URL</th>
                <th>User-Agent</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, req := range a.httpRequests {
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge badge-primary">%s</span></td>
                <td><span class="code">%s</span></td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">%s</td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			req.Timestamp.Format("15:04:05"),
			req.Method,
			req.URL,
			req.UserAgent,
			req.SrcIP,
			req.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateSNMPHTML() string {
	if len(a.snmpMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">📡</div>
            <div>No SNMP messages found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="snmp-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Operation</th>
                <th>Community</th>
                <th>Version</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, msg := range a.snmpMessages {
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge badge-info">%s</span></td>
                <td><strong>%s</strong></td>
                <td>%s</td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			msg.Timestamp.Format("15:04:05"),
			msg.Operation,
			msg.Community,
			msg.Version,
			msg.SrcIP,
			msg.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateLDAPHTML() string {
	if len(a.ldapMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">📂</div>
            <div>No LDAP messages found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="ldap-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Operation</th>
                <th>DN</th>
                <th>Username</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, msg := range a.ldapMessages {
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge badge-success">%s</span></td>
                <td><span class="code">%s</span></td>
                <td>%s</td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			msg.Timestamp.Format("15:04:05"),
			msg.Operation,
			msg.DN,
			msg.Username,
			msg.SrcIP,
			msg.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateSIPHTML() string {
	if len(a.sipMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">📞</div>
            <div>No SIP messages found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="sip-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Method</th>
                <th>From</th>
                <th>To</th>
                <th>Call-ID</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, msg := range a.sipMessages {
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge badge-warning">%s</span></td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="code">%s</span></td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			msg.Timestamp.Format("15:04:05"),
			msg.Method,
			msg.From,
			msg.To,
			msg.CallID,
			msg.SrcIP,
			msg.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateXMPPHTML() string {
	if len(a.xmppMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">💬</div>
            <div>No XMPP messages found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="xmpp-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>From</th>
                <th>To</th>
                <th>Body</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, msg := range a.xmppMessages {
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge badge-danger">%s</span></td>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			msg.Timestamp.Format("15:04:05"),
			msg.Type,
			msg.From,
			msg.To,
			msg.Body,
			msg.SrcIP,
			msg.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateTFTPHTML() string {
	if len(a.tftpTransfers) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">📁</div>
            <div>No TFTP transfers found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="tftp-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Operation</th>
                <th>Filename</th>
                <th>Mode</th>
                <th>Connection</th>
            </tr>
        </thead>
        <tbody>`

	for _, transfer := range a.tftpTransfers {
		opClass := "badge-info"
		if transfer.Operation == "WRQ" {
			opClass = "badge-warning"
		}

		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge %s">%s</span></td>
                <td><strong>%s</strong></td>
                <td>%s</td>
                <td><span class="code">%s → %s</span></td>
            </tr>`,
			transfer.Timestamp.Format("15:04:05"),
			opClass,
			transfer.Operation,
			transfer.Filename,
			transfer.Mode,
			transfer.SrcIP,
			transfer.DstIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}

func (a *Analyzer) generateSyslogHTML() string {
	if len(a.syslogMessages) == 0 {
		return `<div class="empty-state">
            <div class="empty-icon">📋</div>
            <div>No Syslog messages found</div>
        </div>`
	}

	html := `<div class="table-container"><table id="syslog-table">
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Facility</th>
                <th>Hostname</th>
                <th>Message</th>
                <th>Source IP</th>
            </tr>
        </thead>
        <tbody>`

	severityNames := []string{"Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"}

	for _, msg := range a.syslogMessages {
		severityName := "Unknown"
		if msg.Severity >= 0 && msg.Severity < len(severityNames) {
			severityName = severityNames[msg.Severity]
		}

		severityClass := "badge-info"
		if msg.Severity <= 2 {
			severityClass = "badge-danger"
		} else if msg.Severity <= 4 {
			severityClass = "badge-warning"
		}

		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td><span class="badge %s">%s</span></td>
                <td>%d</td>
                <td>%s</td>
                <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis;">%s</td>
                <td><span class="code">%s</span></td>
            </tr>`,
			msg.Timestamp.Format("15:04:05"),
			severityClass,
			severityName,
			msg.Facility,
			msg.Hostname,
			msg.Message,
			msg.SrcIP,
		)
	}

	html += `</tbody></table></div>`
	return html
}


// Export new detection types to CSV
func (a *Analyzer) exportBeaconPatternsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Source IP", "Destination IP", "Destination Port", "Interval", "Jitter", "Confidence", "Packet Count", "Total Bytes"})

	for _, beacon := range a.beaconPatterns {
		writer.Write([]string{
			beacon.StartTime.Format(time.RFC3339),
			beacon.FlowKey.SrcIP,
			beacon.FlowKey.DstIP,
			fmt.Sprintf("%d", beacon.FlowKey.DstPort),
			beacon.Interval.String(),
			fmt.Sprintf("%.3f", beacon.Jitter),
			beacon.Confidence,
			fmt.Sprintf("%d", beacon.PacketCount),
			fmt.Sprintf("%d", beacon.BytesTotal),
		})
	}

	return nil
}

func (a *Analyzer) exportSSHTunnelsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Source IP", "Destination IP", "Destination Port", "Bytes/Sec", "Packets/Sec", "Duration", "Reason", "Confidence"})

	for _, tunnel := range a.sshTunnels {
		writer.Write([]string{
			tunnel.Timestamp.Format(time.RFC3339),
			tunnel.SrcIP,
			tunnel.DstIP,
			fmt.Sprintf("%d", tunnel.DstPort),
			fmt.Sprintf("%.0f", tunnel.BytesPerSecond),
			fmt.Sprintf("%.0f", tunnel.PacketRate),
			fmt.Sprintf("%.0f", tunnel.Duration),
			tunnel.Reason,
			tunnel.Confidence,
		})
	}

	return nil
}

func (a *Analyzer) exportLateralMovementsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Source IP", "Target Count", "Port", "Technique", "Confidence", "Targets"})

	for _, movement := range a.lateralMovements {
		targets := strings.Join(movement.Targets, "; ")
		if len(targets) > 200 {
			targets = targets[:200] + "..."
		}
		
		writer.Write([]string{
			movement.Timestamp.Format(time.RFC3339),
			movement.SrcIP,
			fmt.Sprintf("%d", movement.TargetCount),
			fmt.Sprintf("%d", movement.Port),
			movement.Technique,
			movement.Confidence,
			targets,
		})
	}

	return nil
}

func (a *Analyzer) exportExfiltrationsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Source IP", "Destination IP", "Destination Port", "Bytes Out", "Duration", "Rate (bytes/sec)", "Method", "Confidence"})

	for _, exfil := range a.exfiltrations {
		writer.Write([]string{
			exfil.Timestamp.Format(time.RFC3339),
			exfil.SrcIP,
			exfil.DstIP,
			fmt.Sprintf("%d", exfil.DstPort),
			fmt.Sprintf("%d", exfil.BytesOut),
			exfil.Duration.String(),
			fmt.Sprintf("%.0f", exfil.Rate),
			exfil.Method,
			exfil.Confidence,
		})
	}

	return nil
}

func (a *Analyzer) exportTLSFingerprintsCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Timestamp", "Source IP", "Destination IP", "JA3 Hash", "Server Name", "TLS Version", "Suspicious", "Framework", "Confidence"})

	for _, fp := range a.tlsFingerprints {
		writer.Write([]string{
			fp.Timestamp.Format(time.RFC3339),
			fp.SrcIP,
			fp.DstIP,
			fp.JA3Hash,
			fp.ServerName,
			fp.TLSVersion,
			fmt.Sprintf("%t", fp.Suspicious),
			fp.Framework,
			fp.Confidence,
		})
	}

	return nil
}
