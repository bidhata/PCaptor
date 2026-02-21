package analyzer

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/gopacket/layers"
)

// HTTP credential patterns
var (
	httpAuthRegex = regexp.MustCompile(`(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)`)
	httpFormRegex = regexp.MustCompile(`(?i)(username|user|email)=([^&\s]+).*?(password|pass|pwd)=([^&\s]+)`)
)

func (a *Analyzer) extractFromTCP(tcp *layers.TCP, info PacketInfo) {
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	// HTTP
	if tcp.DstPort == 80 || tcp.SrcPort == 80 || bytes.Contains(payload, []byte("HTTP/")) {
		a.parseHTTP(payload, info)
	}

	// FTP
	if tcp.DstPort == 21 || tcp.SrcPort == 21 {
		a.parseFTP(payload, info)
	}

	// Telnet
	if tcp.DstPort == 23 || tcp.SrcPort == 23 {
		a.parseTelnet(payload, info)
	}

	// SMTP
	if tcp.DstPort == 25 || tcp.SrcPort == 25 || tcp.DstPort == 587 || tcp.SrcPort == 587 {
		a.parseSMTP(payload, info)
	}

	// POP3
	if tcp.DstPort == 110 || tcp.SrcPort == 110 {
		a.parsePOP3(payload, info)
	}

	// IMAP
	if tcp.DstPort == 143 || tcp.SrcPort == 143 {
		a.parseIMAP(payload, info)
	}

	// IRC (ports 6667, 6668, 6669, 7000, or any port with IRC commands)
	if tcp.DstPort >= 6660 && tcp.DstPort <= 7000 || tcp.SrcPort >= 6660 && tcp.SrcPort <= 7000 ||
		bytes.Contains(payload, []byte("PRIVMSG")) || bytes.Contains(payload, []byte("JOIN")) {
		a.parseIRC(payload, info)
	}

	// LDAP
	if tcp.DstPort == 389 || tcp.SrcPort == 389 {
		a.parseLDAP(payload, info)
	}

	// SIP
	if tcp.DstPort == 5060 || tcp.SrcPort == 5060 || 
		bytes.Contains(payload, []byte("SIP/2.0")) || bytes.Contains(payload, []byte("INVITE")) {
		a.parseSIP(payload, info)
	}

	// XMPP/Jabber
	if tcp.DstPort == 5222 || tcp.SrcPort == 5222 || tcp.DstPort == 5269 || tcp.SrcPort == 5269 ||
		bytes.Contains(payload, []byte("<stream:stream")) || bytes.Contains(payload, []byte("<message")) {
		a.parseXMPP(payload, info)
	}

	// Syslog (TCP)
	if tcp.DstPort == 514 || tcp.SrcPort == 514 || tcp.DstPort == 601 || tcp.SrcPort == 601 {
		a.parseSyslog(payload, info)
	}
}

func (a *Analyzer) parseHTTP(payload []byte, info PacketInfo) {
	data := string(payload)

	// Extract HTTP request line
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return
	}

	// Parse request line (GET /path HTTP/1.1)
	requestLine := lines[0]
	parts := strings.Fields(requestLine)
	
	method := ""
	path := ""
	host := ""
	userAgent := ""
	referer := ""
	
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	// Parse headers
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Host:") {
			host = strings.TrimSpace(strings.TrimPrefix(line, "Host:"))
		} else if strings.HasPrefix(line, "User-Agent:") {
			userAgent = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
		} else if strings.HasPrefix(line, "Referer:") {
			referer = strings.TrimSpace(strings.TrimPrefix(line, "Referer:"))
		}
	}

	// Build full URL
	url := ""
	if host != "" && path != "" {
		url = "http://" + host + path
	}

	// Store HTTP request
	if method != "" && url != "" {
		a.addHTTPRequest(HTTPRequest{
			Timestamp: info.Timestamp,
			Method:    method,
			URL:       url,
			Host:      host,
			Path:      path,
			UserAgent: userAgent,
			Referer:   referer,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})

		// Check for C2 patterns
		a.detectC2Patterns(url, host, path, userAgent, info)
		
		// Check for crypto mining
		a.detectCryptoMining(host, url, userAgent, info)
		
		// Check for Tor/VPN/Anonymization
		a.detectTorVPN(host, info.DstIP, info.DstPort, info)
	}

	// Extract credentials from Authorization header
	if matches := httpAuthRegex.FindStringSubmatch(data); len(matches) > 1 {
		decoded, err := base64.StdEncoding.DecodeString(matches[1])
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				username := strings.TrimSpace(parts[0])
				password := strings.TrimSpace(parts[1])
				
				if a.isValidCredential(username, password) {
					a.addCredential(Credential{
						Protocol: "HTTP",
						SrcIP:    info.SrcIP,
						DstIP:    info.DstIP,
						Username: username,
						Password: password,
						Method:   "Basic Auth",
						Strength: calculatePasswordStrength(password),
						Packets:  []int64{info.Number},
					})
				}
			}
		}
	}

	// Extract from form data
	if matches := httpFormRegex.FindStringSubmatch(data); len(matches) > 4 {
		username := matches[2]
		password := matches[4]
		
		if a.isValidCredential(username, password) {
			a.addCredential(Credential{
				Protocol: "HTTP",
				SrcIP:    info.SrcIP,
				DstIP:    info.DstIP,
				Username: username,
				Password: password,
				Method:   "POST Form",
				Strength: calculatePasswordStrength(password),
				Packets:  []int64{info.Number},
			})
		}
	}

	// Extract files
	if strings.Contains(data, "HTTP/1.") && strings.Contains(data, "Content-Type:") {
		a.extractHTTPFile(payload, info)
	}
}

func (a *Analyzer) parseFTP(payload []byte, info PacketInfo) {
	data := string(payload)
	lines := strings.Split(data, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "USER ") {
			username := strings.TrimSpace(line[5:])
			if len(username) >= 3 && len(username) <= 64 {
				a.addCredential(Credential{
					Protocol: "FTP",
					SrcIP:    info.SrcIP,
					DstIP:    info.DstIP,
					Username: username,
					Method:   "USER command",
					Packets:  []int64{info.Number},
				})
			}
		} else if strings.HasPrefix(line, "PASS ") {
			password := strings.TrimSpace(line[5:])
			if len(password) >= 3 && len(password) <= 64 {
				// Find matching username
				a.updateLastCredential("FTP", info.SrcIP, password)
			}
		}
	}
}

func (a *Analyzer) parseTelnet(payload []byte, info PacketInfo) {
	// Filter IAC sequences and control characters
	cleaned := make([]byte, 0, len(payload))
	for i := 0; i < len(payload); i++ {
		b := payload[i]
		if b == 0xFF { // IAC
			i += 2 // Skip IAC sequence
			continue
		}
		if b >= 32 && b <= 126 {
			cleaned = append(cleaned, b)
		}
	}

	data := string(cleaned)
	if len(data) < 3 || len(data) > 100 {
		return
	}

	// Check if it looks like a credential
	if a.looksLikeCredential(data) {
		a.addCredential(Credential{
			Protocol: "Telnet",
			SrcIP:    info.SrcIP,
			DstIP:    info.DstIP,
			Username: data,
			Method:   "Interactive",
			Packets:  []int64{info.Number},
		})
	}
}

func (a *Analyzer) parseSMTP(payload []byte, info PacketInfo) {
	data := string(payload)
	lines := strings.Split(data, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "AUTH LOGIN") || strings.HasPrefix(line, "AUTH PLAIN") {
			// Next lines contain base64 encoded credentials
			continue
		}
		
		// Try to decode as base64
		if len(line) >= 4 && len(line) <= 200 {
			decoded, err := base64.StdEncoding.DecodeString(line)
			if err == nil && len(decoded) >= 3 && len(decoded) <= 100 {
				if a.looksLikeCredential(string(decoded)) {
					a.addCredential(Credential{
						Protocol: "SMTP",
						SrcIP:    info.SrcIP,
						DstIP:    info.DstIP,
						Username: string(decoded),
						Method:   "AUTH LOGIN",
						Packets:  []int64{info.Number},
					})
				}
			}
		}
	}
}

func (a *Analyzer) parsePOP3(payload []byte, info PacketInfo) {
	data := string(payload)
	lines := strings.Split(data, "\r\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "USER ") {
			username := strings.TrimSpace(line[5:])
			if len(username) >= 3 && len(username) <= 64 {
				a.addCredential(Credential{
					Protocol: "POP3",
					SrcIP:    info.SrcIP,
					DstIP:    info.DstIP,
					Username: username,
					Method:   "USER command",
					Packets:  []int64{info.Number},
				})
			}
		} else if strings.HasPrefix(line, "PASS ") {
			password := strings.TrimSpace(line[5:])
			if len(password) >= 3 && len(password) <= 64 {
				a.updateLastCredential("POP3", info.SrcIP, password)
			}
		}
	}
}

func (a *Analyzer) parseIMAP(payload []byte, info PacketInfo) {
	data := string(payload)
	
	// IMAP LOGIN command: tag LOGIN username password
	loginRegex := regexp.MustCompile(`(?i)\w+\s+LOGIN\s+(\S+)\s+(\S+)`)
	if matches := loginRegex.FindStringSubmatch(data); len(matches) > 2 {
		username := strings.Trim(matches[1], `"`)
		password := strings.Trim(matches[2], `"`)
		
		if a.isValidCredential(username, password) {
			a.addCredential(Credential{
				Protocol: "IMAP",
				SrcIP:    info.SrcIP,
				DstIP:    info.DstIP,
				Username: username,
				Password: password,
				Method:   "LOGIN command",
				Strength: calculatePasswordStrength(password),
				Packets:  []int64{info.Number},
			})
		}
	}
}

func (a *Analyzer) parseDNS(dns *layers.DNS, info PacketInfo) {
	// Extract domain names for IOC analysis
	for _, q := range dns.Questions {
		domain := string(q.Name)
		
		// Check for DNS tunneling
		a.detectDNSTunneling(domain, info)
		
		// Check for suspicious domains
		if a.isSuspiciousDomain(domain) {
			a.addThreat(Threat{
				Type:     "Suspicious Domain",
				Severity: "medium",
				Detail:   fmt.Sprintf("DNS query for suspicious domain: %s", domain),
				IOC:      domain,
				Packet:   info.Number,
			})
		}
	}
}

func (a *Analyzer) detectDNSTunneling(domain string, info PacketInfo) {
	domainLower := strings.ToLower(domain)
	
	// Remove trailing dot if present
	domainLower = strings.TrimSuffix(domainLower, ".")
	
	// Split domain into labels
	labels := strings.Split(domainLower, ".")
	if len(labels) < 2 {
		return
	}
	
	// Get subdomain (everything except last 2 labels)
	var subdomain string
	if len(labels) > 2 {
		subdomain = strings.Join(labels[:len(labels)-2], ".")
	}
	
	// 1. Check for unusually long subdomains (common in DNS tunneling)
	if len(subdomain) > 50 {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "DNS Tunneling",
			Indicator:  "Unusually long subdomain",
			Confidence: "medium",
			Detail:     fmt.Sprintf("DNS query with long subdomain (%d chars): %s", len(subdomain), domain),
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        domain,
		})
		
		a.addThreat(Threat{
			Type:     "DNS Tunneling",
			Severity: "high",
			Detail:   fmt.Sprintf("Possible DNS tunneling detected: long subdomain (%d chars)", len(subdomain)),
			IOC:      domain,
			Packet:   info.Number,
		})
		return
	}
	
	// 2. Check for high entropy in subdomain (encrypted/encoded data)
	if len(subdomain) > 20 && a.isHighEntropy(subdomain) {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "DNS Tunneling",
			Indicator:  "High entropy subdomain",
			Confidence: "medium",
			Detail:     fmt.Sprintf("DNS query with high entropy subdomain: %s", domain),
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        domain,
		})
		
		a.addThreat(Threat{
			Type:     "DNS Tunneling",
			Severity: "high",
			Detail:   "Possible DNS tunneling detected: high entropy subdomain",
			IOC:      domain,
			Packet:   info.Number,
		})
		return
	}
	
	// 3. Check for excessive number of subdomains
	if len(labels) > 5 {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "DNS Tunneling",
			Indicator:  "Excessive subdomain levels",
			Confidence: "low",
			Detail:     fmt.Sprintf("DNS query with %d subdomain levels: %s", len(labels)-2, domain),
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        domain,
		})
		
		a.addThreat(Threat{
			Type:     "DNS Tunneling",
			Severity: "medium",
			Detail:   fmt.Sprintf("Possible DNS tunneling: excessive subdomain levels (%d)", len(labels)-2),
			IOC:      domain,
			Packet:   info.Number,
		})
		return
	}
	
	// 4. Check for known DNS tunneling tools
	dnsToolPatterns := []string{
		"dnscat", "iodine", "dns2tcp", "tuns", "ozymandns",
		"heyoka", "dnstunnel", "tcp-over-dns",
	}
	
	for _, pattern := range dnsToolPatterns {
		if strings.Contains(domainLower, pattern) {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "DNS Tunneling",
				Indicator:  "Known DNS tunneling tool: " + pattern,
				Confidence: "high",
				Detail:     fmt.Sprintf("DNS query matches known tunneling tool pattern: %s", domain),
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        domain,
			})
			
			a.addThreat(Threat{
				Type:     "DNS Tunneling",
				Severity: "high",
				Detail:   fmt.Sprintf("Known DNS tunneling tool detected: %s", pattern),
				IOC:      domain,
				Packet:   info.Number,
			})
			return
		}
	}
	
	// 5. Check for base32/base64 patterns in subdomain
	if len(subdomain) > 15 {
		// Count alphanumeric characters
		alphanumCount := 0
		for _, c := range subdomain {
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
				alphanumCount++
			}
		}
		
		// If mostly alphanumeric with few dots, might be encoded
		if float64(alphanumCount)/float64(len(subdomain)) > 0.9 {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "DNS Tunneling",
				Indicator:  "Encoded data in subdomain",
				Confidence: "low",
				Detail:     fmt.Sprintf("DNS query with possible encoded data: %s", domain),
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        domain,
			})
		}
	}
}

func (a *Analyzer) extractHTTPFile(payload []byte, info PacketInfo) {
	// Simple HTTP file extraction
	parts := bytes.Split(payload, []byte("\r\n\r\n"))
	if len(parts) < 2 {
		return
	}

	header := string(parts[0])
	body := parts[1]

	// Extract filename from Content-Disposition
	filenameRegex := regexp.MustCompile(`(?i)filename="?([^";\r\n]+)"?`)
	matches := filenameRegex.FindStringSubmatch(header)
	
	filename := "http_file"
	if len(matches) > 1 {
		filename = sanitizeFilename(matches[1])
	}

	// Save file
	filepath := filepath.Join(a.outputDir, "files", filename)
	if err := os.WriteFile(filepath, body, 0644); err == nil {
		hash := md5.Sum(body)
		a.mu.Lock()
		a.files = append(a.files, ExtractedFile{
			Name:     filename,
			Size:     int64(len(body)),
			MD5:      fmt.Sprintf("%x", hash),
			Protocol: "HTTP",
			Path:     filepath,
		})
		a.mu.Unlock()
	}
}

// Helper functions

func (a *Analyzer) isValidCredential(username, password string) bool {
	// Filter Ethereum addresses
	if strings.HasPrefix(username, "0x") && len(username) >= 40 {
		return false
	}
	
	// Length validation
	if len(username) < 3 || len(username) > 64 {
		return false
	}
	if len(password) < 3 || len(password) > 64 {
		return false
	}
	
	return true
}

func (a *Analyzer) looksLikeCredential(data string) bool {
	if len(data) < 3 || len(data) > 100 {
		return false
	}

	// Count printable characters
	printable := 0
	letters := 0
	for _, r := range data {
		if unicode.IsPrint(r) {
			printable++
		}
		if unicode.IsLetter(r) {
			letters++
		}
	}

	printableRatio := float64(printable) / float64(len(data))
	letterRatio := float64(letters) / float64(len(data))

	return printableRatio >= 0.8 && letterRatio >= 0.3
}

func (a *Analyzer) addCredential(cred Credential) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.credentials = append(a.credentials, cred)
}

func (a *Analyzer) updateLastCredential(protocol, srcIP, password string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Find last credential for this protocol and IP
	for i := len(a.credentials) - 1; i >= 0; i-- {
		if a.credentials[i].Protocol == protocol && 
		   a.credentials[i].SrcIP == srcIP && 
		   a.credentials[i].Password == "" {
			a.credentials[i].Password = password
			a.credentials[i].Strength = calculatePasswordStrength(password)
			return
		}
	}
}

func (a *Analyzer) addThreat(threat Threat) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.threats = append(a.threats, threat)
}

func (a *Analyzer) isSuspiciousDomain(domain string) bool {
	suspicious := []string{
		".tk", ".ml", ".ga", ".cf", ".gq", // Free TLDs
		"pastebin", "ngrok", "duckdns",
	}
	
	for _, pattern := range suspicious {
		if strings.Contains(strings.ToLower(domain), pattern) {
			return true
		}
	}
	return false
}

func sanitizeFilename(name string) string {
	// Remove path separators and dangerous characters
	name = filepath.Base(name)
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' {
			return '_'
		}
		return r
	}, name)
	
	if name == "" {
		name = "file"
	}
	return name
}

func calculatePasswordStrength(password string) int {
	if len(password) == 0 {
		return 0
	}

	score := 0
	
	// Length
	score += len(password) * 4
	
	// Character variety
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	
	for _, r := range password {
		if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}
	
	if hasLower {
		score += 10
	}
	if hasUpper {
		score += 10
	}
	if hasDigit {
		score += 10
	}
	if hasSpecial {
		score += 15
	}
	
	// Cap at 100
	if score > 100 {
		score = 100
	}
	
	return score
}

func (a *Analyzer) parseIRC(payload []byte, info PacketInfo) {
	data := string(payload)
	lines := strings.Split(data, "\r\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		// Parse IRC message format: [:prefix] COMMAND [params] [:trailing]
		var prefix, command, params, trailing string
		
		// Extract prefix if present
		if strings.HasPrefix(line, ":") {
			parts := strings.SplitN(line[1:], " ", 2)
			if len(parts) == 2 {
				prefix = parts[0]
				line = parts[1]
			}
		}

		// Extract trailing if present
		if idx := strings.Index(line, " :"); idx != -1 {
			trailing = line[idx+2:]
			line = line[:idx]
		}

		// Extract command and params
		parts := strings.Fields(line)
		if len(parts) > 0 {
			command = parts[0]
			if len(parts) > 1 {
				params = strings.Join(parts[1:], " ")
			}
		}

		// Extract nick from prefix (nick!user@host)
		nick := ""
		if prefix != "" {
			if idx := strings.Index(prefix, "!"); idx != -1 {
				nick = prefix[:idx]
			} else {
				nick = prefix
			}
		}

		// Process different IRC commands
		switch strings.ToUpper(command) {
		case "PRIVMSG":
			// Private message or channel message
			channel := params
			message := trailing
			
			if channel != "" && message != "" {
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   message,
					Type:      "PRIVMSG",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "NOTICE":
			// Notice message
			channel := params
			message := trailing
			
			if channel != "" && message != "" {
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   message,
					Type:      "NOTICE",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "JOIN":
			// User joining channel
			channel := trailing
			if channel == "" {
				channel = params
			}
			
			if channel != "" {
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   fmt.Sprintf("%s joined %s", nick, channel),
					Type:      "JOIN",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "PART":
			// User leaving channel
			channel := params
			message := trailing
			
			if channel != "" {
				msg := fmt.Sprintf("%s left %s", nick, channel)
				if message != "" {
					msg += fmt.Sprintf(" (%s)", message)
				}
				
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   msg,
					Type:      "PART",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "QUIT":
			// User quitting
			message := trailing
			
			msg := fmt.Sprintf("%s quit", nick)
			if message != "" {
				msg += fmt.Sprintf(" (%s)", message)
			}
			
			a.addIRCMessage(IRCMessage{
				Timestamp: info.Timestamp,
				Channel:   "*",
				Nick:      nick,
				Message:   msg,
				Type:      "QUIT",
				SrcIP:     info.SrcIP,
				DstIP:     info.DstIP,
			})

		case "NICK":
			// Nick change
			newNick := trailing
			if newNick == "" {
				newNick = params
			}
			
			if newNick != "" {
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   "*",
					Nick:      nick,
					Message:   fmt.Sprintf("%s changed nick to %s", nick, newNick),
					Type:      "NICK",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "TOPIC":
			// Channel topic change
			channel := params
			topic := trailing
			
			if channel != "" && topic != "" {
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   fmt.Sprintf("%s changed topic to: %s", nick, topic),
					Type:      "TOPIC",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}

		case "KICK":
			// User kicked from channel
			parts := strings.Fields(params)
			if len(parts) >= 2 {
				channel := parts[0]
				kickedUser := parts[1]
				reason := trailing
				
				msg := fmt.Sprintf("%s kicked %s from %s", nick, kickedUser, channel)
				if reason != "" {
					msg += fmt.Sprintf(" (%s)", reason)
				}
				
				a.addIRCMessage(IRCMessage{
					Timestamp: info.Timestamp,
					Channel:   channel,
					Nick:      nick,
					Message:   msg,
					Type:      "KICK",
					SrcIP:     info.SrcIP,
					DstIP:     info.DstIP,
				})
			}
		}
	}
}

func (a *Analyzer) addIRCMessage(msg IRCMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ircMessages = append(a.ircMessages, msg)
}


func (a *Analyzer) extractFromUDP(udp *layers.UDP, info PacketInfo) {
	payload := udp.Payload
	if len(payload) == 0 {
		return
	}

	// SNMP
	if udp.DstPort == 161 || udp.SrcPort == 161 || udp.DstPort == 162 || udp.SrcPort == 162 {
		a.parseSNMP(payload, info)
	}

	// TFTP
	if udp.DstPort == 69 || udp.SrcPort == 69 {
		a.parseTFTP(payload, info)
	}

	// Syslog (UDP)
	if udp.DstPort == 514 || udp.SrcPort == 514 {
		a.parseSyslog(payload, info)
	}

	// SIP (UDP)
	if udp.DstPort == 5060 || udp.SrcPort == 5060 || 
		bytes.Contains(payload, []byte("SIP/2.0")) || bytes.Contains(payload, []byte("INVITE")) {
		a.parseSIP(payload, info)
	}
}

// SNMP Parser
func (a *Analyzer) parseSNMP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.snmpMessages) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	// Basic SNMP detection - look for ASN.1 sequence tag
	if len(payload) < 10 || payload[0] != 0x30 {
		return
	}
	
	// Try to extract community string (v1/v2c)
	// Community string is typically after version number
	community := ""
	version := "unknown"
	
	// Look for printable strings that might be community strings
	for i := 0; i < len(payload)-4; i++ {
		if payload[i] == 0x04 { // OCTET STRING tag
			length := int(payload[i+1])
			if length > 0 && length < 50 && i+2+length <= len(payload) {
				str := string(payload[i+2 : i+2+length])
				if isPrintable(str) && len(str) >= 3 {
					if community == "" {
						community = str
					}
				}
			}
		}
	}

	// Detect operation type
	operation := "UNKNOWN"
	if bytes.Contains(payload, []byte{0xa0}) {
		operation = "GET-REQUEST"
	} else if bytes.Contains(payload, []byte{0xa1}) {
		operation = "GET-NEXT-REQUEST"
	} else if bytes.Contains(payload, []byte{0xa2}) {
		operation = "GET-RESPONSE"
	} else if bytes.Contains(payload, []byte{0xa3}) {
		operation = "SET-REQUEST"
	} else if bytes.Contains(payload, []byte{0xa4}) {
		operation = "TRAP"
	}

	if community != "" || operation != "UNKNOWN" {
		a.addSNMPMessage(SNMPMessage{
			Timestamp: info.Timestamp,
			Version:   version,
			Community: community,
			Operation: operation,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})

		// Add threat if community string found
		if community != "" {
			a.addThreat(Threat{
				Type:     "SNMP Community String",
				Severity: "medium",
				Detail:   fmt.Sprintf("SNMP %s with community string: %s", operation, community),
				IOC:      community,
			})
		}
	}
}

// LDAP Parser
func (a *Analyzer) parseLDAP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.ldapMessages) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	// Basic LDAP detection - ASN.1 sequence
	if len(payload) < 10 || payload[0] != 0x30 {
		return
	}
	
	// Detect LDAP operations
	operation := ""
	dn := ""
	username := ""
	password := ""
	
	// BIND request (0x60)
	if bytes.Contains(payload, []byte{0x60}) {
		operation = "BIND"
		
		// Try to extract DN and password
		for i := 0; i < len(payload)-4; i++ {
			if payload[i] == 0x04 { // OCTET STRING
				length := int(payload[i+1])
				if length > 0 && length < 200 && i+2+length <= len(payload) {
					str := string(payload[i+2 : i+2+length])
					if isPrintable(str) && len(str) >= 3 {
						if strings.Contains(str, "cn=") || strings.Contains(str, "uid=") || strings.Contains(str, "dc=") {
							dn = str
						} else if dn != "" && password == "" {
							password = str
						}
					}
				}
			}
		}
		
		if dn != "" {
			username = dn
		}
	} else if bytes.Contains(payload, []byte{0x63}) {
		operation = "SEARCH"
	} else if bytes.Contains(payload, []byte{0x68}) {
		operation = "ADD"
	} else if bytes.Contains(payload, []byte{0x66}) {
		operation = "MODIFY"
	}

	if operation != "" {
		a.addLDAPMessage(LDAPMessage{
			Timestamp: info.Timestamp,
			Operation: operation,
			DN:        dn,
			Username:  username,
			Password:  password,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})

		// Add credential if found
		if username != "" && password != "" {
			a.addCredential(Credential{
				Protocol: "LDAP",
				SrcIP:    info.SrcIP,
				DstIP:    info.DstIP,
				Username: username,
				Password: password,
				Method:   "BIND",
				Strength: calculatePasswordStrength(password),
			})
		}
	}
}

// SIP Parser
func (a *Analyzer) parseSIP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.sipMessages) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	data := string(payload)
	lines := strings.Split(data, "\r\n")
	
	if len(lines) == 0 {
		return
	}

	method := ""
	from := ""
	to := ""
	callID := ""
	userAgent := ""
	auth := ""

	// Parse first line for method
	firstLine := lines[0]
	if strings.HasPrefix(firstLine, "INVITE") {
		method = "INVITE"
	} else if strings.HasPrefix(firstLine, "REGISTER") {
		method = "REGISTER"
	} else if strings.HasPrefix(firstLine, "BYE") {
		method = "BYE"
	} else if strings.HasPrefix(firstLine, "ACK") {
		method = "ACK"
	} else if strings.HasPrefix(firstLine, "CANCEL") {
		method = "CANCEL"
	} else if strings.HasPrefix(firstLine, "OPTIONS") {
		method = "OPTIONS"
	}

	// Parse headers
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "From:") || strings.HasPrefix(line, "f:") {
			from = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "From:"), "f:"))
		} else if strings.HasPrefix(line, "To:") || strings.HasPrefix(line, "t:") {
			to = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "To:"), "t:"))
		} else if strings.HasPrefix(line, "Call-ID:") || strings.HasPrefix(line, "i:") {
			callID = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Call-ID:"), "i:"))
		} else if strings.HasPrefix(line, "User-Agent:") {
			userAgent = strings.TrimSpace(strings.TrimPrefix(line, "User-Agent:"))
		} else if strings.HasPrefix(line, "Authorization:") || strings.HasPrefix(line, "Proxy-Authorization:") {
			auth = strings.TrimSpace(line)
		}
	}

	if method != "" {
		a.addSIPMessage(SIPMessage{
			Timestamp: info.Timestamp,
			Method:    method,
			From:      from,
			To:        to,
			CallID:    callID,
			UserAgent: userAgent,
			Auth:      auth,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})

		// Add threat for call activity
		if method == "INVITE" {
			a.addThreat(Threat{
				Type:     "VoIP Call",
				Severity: "low",
				Detail:   fmt.Sprintf("SIP call from %s to %s", from, to),
				IOC:      callID,
			})
		}
	}
}

// XMPP Parser
func (a *Analyzer) parseXMPP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.xmppMessages) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	data := string(payload)
	
	// Look for XMPP message stanzas
	msgType := ""
	from := ""
	to := ""
	body := ""
	subject := ""

	if strings.Contains(data, "<message") {
		msgType = "message"
		
		// Extract from attribute
		if idx := strings.Index(data, "from='"); idx != -1 {
			end := strings.Index(data[idx+6:], "'")
			if end != -1 {
				from = data[idx+6 : idx+6+end]
			}
		} else if idx := strings.Index(data, `from="`); idx != -1 {
			end := strings.Index(data[idx+6:], `"`)
			if end != -1 {
				from = data[idx+6 : idx+6+end]
			}
		}

		// Extract to attribute
		if idx := strings.Index(data, "to='"); idx != -1 {
			end := strings.Index(data[idx+4:], "'")
			if end != -1 {
				to = data[idx+4 : idx+4+end]
			}
		} else if idx := strings.Index(data, `to="`); idx != -1 {
			end := strings.Index(data[idx+4:], `"`)
			if end != -1 {
				to = data[idx+4 : idx+4+end]
			}
		}

		// Extract body
		if idx := strings.Index(data, "<body>"); idx != -1 {
			end := strings.Index(data[idx:], "</body>")
			if end != -1 {
				body = data[idx+6 : idx+end]
			}
		}

		// Extract subject
		if idx := strings.Index(data, "<subject>"); idx != -1 {
			end := strings.Index(data[idx:], "</subject>")
			if end != -1 {
				subject = data[idx+9 : idx+end]
			}
		}
	} else if strings.Contains(data, "<presence") {
		msgType = "presence"
	} else if strings.Contains(data, "<iq") {
		msgType = "iq"
	}

	if msgType != "" && (from != "" || to != "") {
		a.addXMPPMessage(XMPPMessage{
			Timestamp: info.Timestamp,
			Type:      msgType,
			From:      from,
			To:        to,
			Body:      body,
			Subject:   subject,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})
	}
}

// TFTP Parser
func (a *Analyzer) parseTFTP(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.tftpTransfers) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	if len(payload) < 4 {
		return
	}

	// TFTP opcode is first 2 bytes
	opcode := int(payload[0])<<8 | int(payload[1])
	
	operation := ""
	filename := ""
	mode := ""

	switch opcode {
	case 1: // RRQ (Read Request)
		operation = "RRQ"
		// Filename is null-terminated string after opcode
		nullIdx := bytes.IndexByte(payload[2:], 0)
		if nullIdx != -1 {
			filename = string(payload[2 : 2+nullIdx])
			// Mode is after filename
			if 2+nullIdx+1 < len(payload) {
				nullIdx2 := bytes.IndexByte(payload[2+nullIdx+1:], 0)
				if nullIdx2 != -1 {
					mode = string(payload[2+nullIdx+1 : 2+nullIdx+1+nullIdx2])
				}
			}
		}
	case 2: // WRQ (Write Request)
		operation = "WRQ"
		nullIdx := bytes.IndexByte(payload[2:], 0)
		if nullIdx != -1 {
			filename = string(payload[2 : 2+nullIdx])
			if 2+nullIdx+1 < len(payload) {
				nullIdx2 := bytes.IndexByte(payload[2+nullIdx+1:], 0)
				if nullIdx2 != -1 {
					mode = string(payload[2+nullIdx+1 : 2+nullIdx+1+nullIdx2])
				}
			}
		}
	}

	if operation != "" && filename != "" {
		a.addTFTPTransfer(TFTPTransfer{
			Timestamp: info.Timestamp,
			Operation: operation,
			Filename:  filename,
			Mode:      mode,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})

		// Add threat for TFTP activity (no authentication)
		a.addThreat(Threat{
			Type:     "TFTP Transfer",
			Severity: "medium",
			Detail:   fmt.Sprintf("TFTP %s: %s (no authentication)", operation, filename),
			IOC:      filename,
		})
	}
}

// Syslog Parser
func (a *Analyzer) parseSyslog(payload []byte, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.syslogMessages) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	data := string(payload)
	if len(data) < 5 {
		return
	}

	// Syslog format: <PRI>TIMESTAMP HOSTNAME MESSAGE
	// PRI = Facility * 8 + Severity
	
	facility := 0
	severity := 0
	hostname := ""
	message := data

	// Extract priority if present
	if data[0] == '<' {
		endIdx := strings.Index(data, ">")
		if endIdx != -1 && endIdx < 10 {
			priStr := data[1:endIdx]
			if pri, err := fmt.Sscanf(priStr, "%d", &facility); err == nil && pri == 1 {
				severity = facility % 8
				facility = facility / 8
				message = strings.TrimSpace(data[endIdx+1:])
			}
		}
	}

	// Try to extract hostname (first word after priority)
	parts := strings.Fields(message)
	if len(parts) > 0 {
		// Skip timestamp if present
		if !strings.Contains(parts[0], ":") {
			hostname = parts[0]
			if len(parts) > 1 {
				message = strings.Join(parts[1:], " ")
			}
		}
	}

	if len(message) > 0 {
		a.addSyslogMessage(SyslogMessage{
			Timestamp: info.Timestamp,
			Facility:  facility,
			Severity:  severity,
			Hostname:  hostname,
			Message:   message,
			SrcIP:     info.SrcIP,
			DstIP:     info.DstIP,
		})
	}
}

// Helper functions for adding messages
func (a *Analyzer) addSNMPMessage(msg SNMPMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.snmpMessages) < a.maxMessages {
		a.snmpMessages = append(a.snmpMessages, msg)
	}
}

func (a *Analyzer) addLDAPMessage(msg LDAPMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.ldapMessages) < a.maxMessages {
		a.ldapMessages = append(a.ldapMessages, msg)
	}
}

func (a *Analyzer) addSIPMessage(msg SIPMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.sipMessages) < a.maxMessages {
		a.sipMessages = append(a.sipMessages, msg)
	}
}

func (a *Analyzer) addXMPPMessage(msg XMPPMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.xmppMessages) < a.maxMessages {
		a.xmppMessages = append(a.xmppMessages, msg)
	}
}

func (a *Analyzer) addTFTPTransfer(transfer TFTPTransfer) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.tftpTransfers) < a.maxMessages {
		a.tftpTransfers = append(a.tftpTransfers, transfer)
	}
}

func (a *Analyzer) addSyslogMessage(msg SyslogMessage) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.syslogMessages) < a.maxMessages {
		a.syslogMessages = append(a.syslogMessages, msg)
	}
}

// Helper function to check if string is printable
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}


// C2 Detection Patterns
func (a *Analyzer) detectC2Patterns(url, host, path, userAgent string, info PacketInfo) {
	// Check message count limit
	a.mu.RLock()
	if len(a.c2Detections) >= a.maxMessages {
		a.mu.RUnlock()
		return
	}
	a.mu.RUnlock()

	urlLower := strings.ToLower(url)
	pathLower := strings.ToLower(path)
	uaLower := strings.ToLower(userAgent)
	hostLower := strings.ToLower(host)

	// Cobalt Strike Patterns
	if a.detectCobaltStrike(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Metasploit Patterns
	if a.detectMetasploit(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Empire Patterns
	if a.detectEmpire(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Covenant Patterns
	if a.detectCovenant(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Sliver C2
	if a.detectSliver(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Mythic C2
	if a.detectMythic(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Brute Ratel
	if a.detectBruteRatel(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// PoshC2
	if a.detectPoshC2(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Havoc C2
	if a.detectHavoc(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Pupy RAT
	if a.detectPupy(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Koadic
	if a.detectKoadic(urlLower, pathLower, uaLower, url, info) {
		return
	}

	// Behavioral Analysis
	a.detectC2Behavior(urlLower, pathLower, uaLower, hostLower, url, info)

	// Generic C2 Patterns
	a.detectGenericC2(urlLower, pathLower, uaLower, url, info)
}

func (a *Analyzer) detectCobaltStrike(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Cobalt Strike default URIs (expanded list)
	csURIs := []string{
		"/activity", "/admin", "/api", "/beacon", "/ca", "/config",
		"/download", "/fakeurl", "/file", "/files", "/follow", "/g",
		"/ga.js", "/gaq", "/get", "/ie", "/jquery", "/login",
		"/mail", "/match", "/mobile", "/news", "/pixel", "/push",
		"/ptj", "/ptk", "/rest", "/s", "/search", "/submit",
		"/updates", "/upload", "/visit", "/vue", "/wpad.dat",
		"/__utm.gif", "/cm", "/cx", "/en_us/all.js", "/functionalScript/",
		"/ga", "/include.js", "/j.ad", "/j/", "/jquery-3", "/load",
		"/match", "/pixel.gif", "/push", "/status", "/submit.php",
		"/updates.rss", "/visit.js",
	}

	for _, uri := range csURIs {
		if pathLower == uri || strings.HasPrefix(pathLower, uri+".") {
			indicator = "Cobalt Strike default URI: " + uri
			confidence = "medium"
			detected = true
			break
		}
	}

	// Cobalt Strike User-Agents (expanded)
	csUserAgents := []string{
		"internet explorer",
		"mozilla/4.0 (compatible; msie",
		"mozilla/5.0 (windows nt 6.1; wow64; trident/",
		"mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36",
	}

	for _, ua := range csUserAgents {
		if strings.Contains(uaLower, ua) && detected {
			confidence = "high"
			indicator += " + Cobalt Strike User-Agent pattern"
			break
		}
	}

	// Cobalt Strike Malleable C2 patterns
	if strings.Contains(pathLower, "/jquery-") && strings.Contains(pathLower, ".min.js") {
		indicator = "Cobalt Strike Malleable C2 jQuery pattern"
		confidence = "medium"
		detected = true
	}

	if strings.Contains(pathLower, "/ga.js") || strings.Contains(pathLower, "/__utm.gif") {
		indicator = "Cobalt Strike Google Analytics mimicry"
		confidence = "medium"
		detected = true
	}

	// Check for Cobalt Strike stager patterns
	if strings.Contains(pathLower, "/functionalscript/") || 
	   strings.Contains(pathLower, "/en_us/all.js") {
		indicator = "Cobalt Strike stager URI pattern"
		confidence = "high"
		detected = true
	}

	// Check for checksum8 algorithm pattern (4 char paths)
	if len(pathLower) == 5 && pathLower[0] == '/' && !strings.Contains(pathLower, ".") {
		// Possible CS checksum8 URI
		indicator = "Possible Cobalt Strike checksum8 URI"
		confidence = "low"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Cobalt Strike",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     fmt.Sprintf("Detected Cobalt Strike C2 pattern in HTTP traffic"),
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Cobalt Strike C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectMetasploit(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Metasploit default URIs (expanded)
	msfURIs := []string{
		"/msf", "/meterpreter", "/metasploit", "/payload",
		"/shell", "/cmd", "/exec", "/reverse", "/bind",
		"/stager", "/stage", "/download", "/upload",
		"/api/", "/console", "/sessions",
	}

	for _, uri := range msfURIs {
		if strings.Contains(pathLower, uri) {
			indicator = "Metasploit URI pattern: " + uri
			confidence = "medium"
			detected = true
			break
		}
	}

	// Metasploit User-Agents
	if strings.Contains(uaLower, "metasploit") || 
	   strings.Contains(uaLower, "meterpreter") ||
	   strings.Contains(uaLower, "msf/") {
		indicator = "Metasploit User-Agent"
		confidence = "high"
		detected = true
	}

	// Check for Meterpreter reverse HTTPS patterns
	if strings.Contains(pathLower, "/abcdefghijklmnopqrstuvwxyz") ||
	   strings.Contains(pathLower, "/123456789") {
		indicator = "Meterpreter reverse HTTPS pattern"
		confidence = "high"
		detected = true
	}

	// Check for common Metasploit payload patterns
	if strings.Contains(pathLower, "checksum=") && len(pathLower) > 30 {
		indicator = "Metasploit payload checksum pattern"
		confidence = "medium"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Metasploit",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Metasploit Framework C2 pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Metasploit C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectEmpire(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Empire default URIs
	empireURIs := []string{
		"/admin/get.php", "/news.php", "/login/process.php",
		"/admin/news.php", "/admin/get", "/news.asp",
	}

	for _, uri := range empireURIs {
		if pathLower == uri {
			indicator = "Empire default URI: " + uri
			confidence = "high"
			detected = true
			break
		}
	}

	// Empire User-Agents
	if strings.Contains(uaLower, "empire") {
		indicator = "Empire User-Agent"
		confidence = "high"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Empire",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected PowerShell Empire C2 pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Empire C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectCovenant(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Covenant patterns
	if strings.Contains(pathLower, "/covenant") {
		indicator = "Covenant URI pattern"
		confidence = "medium"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Covenant",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Covenant C2 pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Covenant C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectGenericC2(urlLower, pathLower, uaLower, url string, info PacketInfo) {
	// Generic suspicious patterns (expanded)
	suspiciousPatterns := []string{
		"/c2/", "/command", "/control", "/backdoor", "/rat",
		"/trojan", "/malware", "/bot", "/agent", "/implant",
		"/callback", "/checkin", "/heartbeat", "/beacon",
		"/tasks", "/results", "/exfil", "/data",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(pathLower, pattern) {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "Generic",
				Indicator:  "Suspicious URI pattern: " + pattern,
				Confidence: "low",
				Detail:     "Detected generic C2-like pattern in URI",
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        url,
			})

			a.addThreat(Threat{
				Type:     "Suspicious Activity",
				Severity: "medium",
				Detail:   fmt.Sprintf("Suspicious C2-like URI pattern: %s", pattern),
				IOC:      url,
			})
			return
		}
	}

	// Check for base64 encoded data in URI (common in C2)
	if len(pathLower) > 50 {
		// Count base64-like characters
		base64Chars := 0
		for _, c := range pathLower {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
			   (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
				base64Chars++
			}
		}
		
		// If more than 80% are base64 chars, likely encoded
		if float64(base64Chars)/float64(len(pathLower)) > 0.8 {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "Generic",
				Indicator:  "Base64-encoded URI data",
				Confidence: "low",
				Detail:     "URI contains potential base64 encoded data (common in C2)",
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        url,
			})

			a.addThreat(Threat{
				Type:     "Suspicious Activity",
				Severity: "low",
				Detail:   "URI contains potential base64 encoded data",
				IOC:      url,
			})
			return
		}
	}

	// Check for hex-encoded data in URI
	if len(pathLower) > 40 && strings.Count(pathLower, "%") > 5 {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Generic",
			Indicator:  "URL-encoded data in URI",
			Confidence: "low",
			Detail:     "URI contains heavily URL-encoded data (possible obfuscation)",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})
	}

	// Check for UUID-like patterns (common in modern C2)
	if strings.Count(pathLower, "-") >= 4 && len(pathLower) > 30 {
		// Looks like UUID pattern
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Generic",
			Indicator:  "UUID-like pattern in URI",
			Confidence: "low",
			Detail:     "URI contains UUID-like identifier (common in modern C2)",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})
	}
}

func (a *Analyzer) detectSliver(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Sliver C2 patterns
	sliverPaths := []string{
		"/sliver", "/stage", "/stager", "/beacon",
	}

	for _, path := range sliverPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Sliver C2 URI pattern: " + path
			confidence = "medium"
			detected = true
			break
		}
	}

	// Sliver often uses long random paths
	if len(pathLower) > 32 && !strings.Contains(pathLower, ".") {
		// Check if path looks random (high entropy)
		if a.isHighEntropy(pathLower) {
			indicator = "Sliver-like high entropy URI"
			confidence = "low"
			detected = true
		}
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Sliver",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Sliver C2 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Sliver C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectMythic(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Mythic C2 patterns
	mythicPaths := []string{
		"/mythic", "/api/v1.4/", "/new/callback", "/agent_message",
	}

	for _, path := range mythicPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Mythic C2 URI pattern: " + path
			confidence = "high"
			detected = true
			break
		}
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Mythic",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Mythic C2 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Mythic C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectBruteRatel(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Brute Ratel C4 patterns
	bruteRatelPaths := []string{
		"/brute", "/ratel", "/c4/", "/badger",
	}

	for _, path := range bruteRatelPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Brute Ratel C4 URI pattern: " + path
			confidence = "medium"
			detected = true
			break
		}
	}

	// Brute Ratel User-Agent patterns
	if strings.Contains(uaLower, "badger") {
		indicator = "Brute Ratel User-Agent pattern"
		confidence = "high"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Brute Ratel C4",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Brute Ratel C4 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Brute Ratel C4 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectPoshC2(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// PoshC2 patterns
	poshPaths := []string{
		"/posh", "/implant", "/mobile", "/news.php", "/download.aspx",
	}

	for _, path := range poshPaths {
		if strings.Contains(pathLower, path) {
			indicator = "PoshC2 URI pattern: " + path
			confidence = "medium"
			detected = true
			break
		}
	}

	// PoshC2 often uses specific User-Agents
	poshUA := []string{
		"posh", "implant",
	}

	for _, ua := range poshUA {
		if strings.Contains(uaLower, ua) {
			indicator = "PoshC2 User-Agent pattern"
			confidence = "high"
			detected = true
			break
		}
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "PoshC2",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected PoshC2 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("PoshC2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectHavoc(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Havoc C2 patterns
	havocPaths := []string{
		"/havoc", "/demon", "/listener",
	}

	for _, path := range havocPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Havoc C2 URI pattern: " + path
			confidence = "medium"
			detected = true
			break
		}
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Havoc",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Havoc C2 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Havoc C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectPupy(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Pupy RAT patterns
	pupyPaths := []string{
		"/pupy", "/pupyrat", "/connect",
	}

	for _, path := range pupyPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Pupy RAT URI pattern: " + path
			confidence = "high"
			detected = true
			break
		}
	}

	if strings.Contains(uaLower, "pupy") {
		indicator = "Pupy RAT User-Agent"
		confidence = "high"
		detected = true
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Pupy RAT",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Pupy RAT pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Pupy RAT detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectKoadic(urlLower, pathLower, uaLower, url string, info PacketInfo) bool {
	detected := false
	confidence := "low"
	indicator := ""

	// Koadic patterns
	koadicPaths := []string{
		"/koadic", "/stage", "/stager",
	}

	for _, path := range koadicPaths {
		if strings.Contains(pathLower, path) {
			indicator = "Koadic URI pattern: " + path
			confidence = "medium"
			detected = true
			break
		}
	}

	if detected {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Koadic",
			Indicator:  indicator,
			Confidence: confidence,
			Detail:     "Detected Koadic C2 framework pattern",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})

		a.addThreat(Threat{
			Type:     "C2 Communication",
			Severity: "high",
			Detail:   fmt.Sprintf("Koadic C2 detected: %s (%s confidence)", indicator, confidence),
			IOC:      url,
		})
	}

	return detected
}

func (a *Analyzer) detectC2Behavior(urlLower, pathLower, uaLower, hostLower, url string, info PacketInfo) {
	// Behavioral analysis for C2 detection
	
	// 1. Check for suspicious User-Agent patterns
	suspiciousUA := []string{
		"python-requests", "curl/", "wget/", "powershell",
		"go-http-client", "java/", "ruby", "perl",
	}
	
	for _, ua := range suspiciousUA {
		if strings.Contains(uaLower, ua) {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "Behavioral",
				Indicator:  "Suspicious User-Agent: " + ua,
				Confidence: "low",
				Detail:     "Non-browser User-Agent detected (common in C2)",
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        url,
			})
			return
		}
	}

	// 2. Check for long random-looking paths (high entropy)
	if len(pathLower) > 40 && a.isHighEntropy(pathLower) {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Behavioral",
			Indicator:  "High entropy URI path",
			Confidence: "low",
			Detail:     "URI contains high entropy data (possible encrypted C2)",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})
		return
	}

	// 3. Check for suspicious file extensions in paths
	suspiciousExts := []string{
		".php?", ".asp?", ".jsp?", ".cgi?",
	}
	
	for _, ext := range suspiciousExts {
		if strings.Contains(pathLower, ext) && len(pathLower) > 50 {
			a.addC2Detection(C2Detection{
				Timestamp:  info.Timestamp,
				Framework:  "Behavioral",
				Indicator:  "Suspicious script with long parameters",
				Confidence: "low",
				Detail:     "Script file with unusually long parameters (possible C2)",
				SrcIP:      info.SrcIP,
				DstIP:      info.DstIP,
				URL:        url,
			})
			return
		}
	}

	// 4. Check for IP addresses in Host header (not domain names)
	if a.isIPAddress(hostLower) {
		a.addC2Detection(C2Detection{
			Timestamp:  info.Timestamp,
			Framework:  "Behavioral",
			Indicator:  "Direct IP communication",
			Confidence: "low",
			Detail:     "HTTP request to IP address instead of domain (common in C2)",
			SrcIP:      info.SrcIP,
			DstIP:      info.DstIP,
			URL:        url,
		})
		return
	}

	// 5. Check for unusual port numbers in URL
	if strings.Contains(hostLower, ":") {
		parts := strings.Split(hostLower, ":")
		if len(parts) == 2 {
			port := parts[1]
			// Common non-standard ports used by C2
			suspiciousPorts := []string{"8080", "8443", "8888", "4444", "5555", "6666", "7777", "9999"}
			for _, sp := range suspiciousPorts {
				if port == sp {
					a.addC2Detection(C2Detection{
						Timestamp:  info.Timestamp,
						Framework:  "Behavioral",
						Indicator:  "Suspicious port: " + port,
						Confidence: "low",
						Detail:     "Communication on non-standard port (common in C2)",
						SrcIP:      info.SrcIP,
						DstIP:      info.DstIP,
						URL:        url,
					})
					return
				}
			}
		}
	}
}

// Helper function to check if string has high entropy (randomness)
func (a *Analyzer) isHighEntropy(s string) bool {
	if len(s) < 10 {
		return false
	}
	
	// Count unique characters
	charMap := make(map[rune]int)
	for _, c := range s {
		charMap[c]++
	}
	
	// Calculate entropy
	entropy := 0.0
	length := float64(len(s))
	for _, count := range charMap {
		freq := float64(count) / length
		if freq > 0 {
			entropy -= freq * (float64(count) / length)
		}
	}
	
	// High entropy threshold (more unique characters = higher entropy)
	uniqueRatio := float64(len(charMap)) / length
	return uniqueRatio > 0.6 // More than 60% unique characters
}

// Helper function to check if string is an IP address
func (a *Analyzer) isIPAddress(s string) bool {
	// Remove port if present
	if strings.Contains(s, ":") {
		s = strings.Split(s, ":")[0]
	}
	
	// Simple IPv4 check
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	
	return true
}

// Helper functions
func (a *Analyzer) addHTTPRequest(req HTTPRequest) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.httpRequests) < a.maxMessages {
		a.httpRequests = append(a.httpRequests, req)
	}
}

func (a *Analyzer) addC2Detection(detection C2Detection) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.c2Detections) < a.maxMessages {
		a.c2Detections = append(a.c2Detections, detection)
	}
}
