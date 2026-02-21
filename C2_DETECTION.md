# Enhanced C2 Detection Capabilities

## Overview
EasyPCAP now includes comprehensive Command & Control (C2) detection using multiple advanced methods including signature-based detection, behavioral analysis, and DNS tunneling detection.

## Detection Methods

### 1. Signature-Based Detection

#### Supported C2 Frameworks (11 Total)

1. **Cobalt Strike**
   - Default URIs (40+ patterns)
   - Malleable C2 profiles
   - jQuery/Google Analytics mimicry
   - Checksum8 algorithm patterns
   - Stager URI patterns
   - User-Agent fingerprinting

2. **Metasploit Framework**
   - Default URIs and paths
   - Meterpreter patterns
   - Reverse HTTPS signatures
   - Payload checksum patterns
   - User-Agent detection

3. **PowerShell Empire**
   - Default URIs (admin/get.php, news.php, etc.)
   - User-Agent patterns
   - Empire-specific endpoints

4. **Covenant**
   - URI patterns
   - Framework-specific indicators

5. **Sliver** (NEW)
   - Default paths
   - High entropy URI detection
   - Stager patterns

6. **Mythic** (NEW)
   - API endpoint patterns
   - Callback URIs
   - Agent message patterns

7. **Brute Ratel C4** (NEW)
   - URI patterns
   - Badger User-Agent
   - C4-specific indicators

8. **PoshC2** (NEW)
   - Implant URIs
   - Mobile/news.php patterns
   - User-Agent fingerprinting

9. **Havoc** (NEW)
   - Demon agent patterns
   - Listener URIs

10. **Pupy RAT** (NEW)
    - Connection patterns
    - User-Agent detection

11. **Koadic** (NEW)
    - Stage/stager patterns
    - Framework-specific URIs

### 2. Behavioral Analysis

#### HTTP Traffic Analysis
- **Non-Browser User-Agents**: Detects automated tools
  - python-requests, curl, wget
  - PowerShell, Go HTTP client
  - Java, Ruby, Perl clients

- **High Entropy URIs**: Identifies encrypted/encoded C2 traffic
  - Analyzes character distribution
  - Detects random-looking paths (>60% unique chars)
  - Flags URIs longer than 40 characters

- **Suspicious Script Parameters**
  - PHP/ASP/JSP with long query strings
  - Unusual parameter patterns

- **Direct IP Communication**
  - HTTP requests to IP addresses instead of domains
  - Common in C2 to avoid DNS logging

- **Non-Standard Ports**
  - Detects communication on suspicious ports
  - 8080, 8443, 8888, 4444, 5555, 6666, 7777, 9999

### 3. DNS Tunneling Detection

#### Detection Techniques

1. **Long Subdomain Analysis**
   - Flags subdomains longer than 50 characters
   - Common in data exfiltration via DNS

2. **High Entropy Subdomains**
   - Detects encrypted/encoded data in DNS queries
   - Analyzes character randomness

3. **Excessive Subdomain Levels**
   - Identifies queries with more than 5 subdomain levels
   - Unusual for legitimate traffic

4. **Known DNS Tunneling Tools**
   - dnscat, dnscat2
   - iodine
   - dns2tcp
   - tuns, ozymandns
   - heyoka, dnstunnel
   - tcp-over-dns

5. **Encoded Data Detection**
   - Base32/Base64 patterns in subdomains
   - High alphanumeric ratio (>90%)

### 4. Generic C2 Pattern Detection

#### URI Pattern Analysis
- Suspicious keywords: /c2/, /command, /control, /backdoor, /rat
- Malware indicators: /trojan, /malware, /bot, /agent, /implant
- C2 operations: /callback, /checkin, /heartbeat, /beacon
- Data exfiltration: /tasks, /results, /exfil, /data

#### Encoding Detection
- **Base64 Encoded URIs**
  - Detects URIs with >80% base64 characters
  - Common in obfuscated C2 traffic

- **URL Encoding**
  - Heavy use of percent-encoding (>5 occurrences)
  - Possible obfuscation technique

- **UUID Patterns**
  - Detects UUID-like identifiers in URIs
  - Common in modern C2 frameworks

## Confidence Levels

### High Confidence
- Known framework signatures with multiple indicators
- Specific User-Agent + URI pattern matches
- Known DNS tunneling tool patterns
- Long DNS subdomains (>50 chars)

### Medium Confidence
- Single framework indicator match
- High entropy URIs/DNS queries
- Suspicious port usage
- Excessive subdomain levels

### Low Confidence
- Generic suspicious patterns
- Non-browser User-Agents
- Encoded data in URIs
- Behavioral anomalies

## Output Formats

### HTML Report
- Dedicated C2 Detection tab
- Color-coded confidence badges
- Framework identification
- Indicator details
- Source/destination IPs
- Full URL context

### CSV Export
- Timestamp
- Framework name
- Indicator type
- Confidence level
- Detail description
- URL/domain
- Source/destination IPs

### JSON Export
- Complete C2 detection data
- Structured format for SIEM integration
- All metadata included

## Detection Statistics

### Test Results (capture.pcap)
- **Total C2 Detections**: 10,997
- **Frameworks Detected**: Multiple
- **DNS Tunneling Attempts**: Analyzed
- **Behavioral Anomalies**: Identified
- **Processing Time**: 6.7 seconds for 506K packets

## Integration with Threat Detection

All C2 detections automatically generate corresponding threat entries:
- **Severity Levels**: High, Medium, Low
- **Threat Types**: C2 Communication, DNS Tunneling, Suspicious Activity
- **IOC Extraction**: URLs, domains, IPs
- **Threat Score**: Contributes to overall threat score

## Advanced Features

### Entropy Analysis
- Shannon entropy calculation
- Character distribution analysis
- Randomness detection for encrypted traffic

### IP Address Detection
- Identifies direct IP communication
- Separates from domain-based traffic
- Flags unusual patterns

### Pattern Matching
- Regular expression support
- Multi-pattern matching
- Case-insensitive analysis

## Use Cases

1. **Incident Response**
   - Identify active C2 channels
   - Extract IOCs for blocking
   - Timeline reconstruction

2. **Threat Hunting**
   - Proactive C2 detection
   - Behavioral anomaly identification
   - DNS tunneling discovery

3. **Forensic Analysis**
   - Post-breach investigation
   - C2 framework identification
   - Communication pattern analysis

4. **Security Monitoring**
   - Real-time threat detection
   - SIEM integration via JSON/CSV
   - Alert generation

## Limitations

- Signature-based detection can be evaded with custom profiles
- Behavioral analysis may generate false positives
- Encrypted C2 traffic (HTTPS) limits deep inspection
- DNS tunneling detection based on heuristics

## Future Enhancements

- Machine learning-based detection
- JA3/JA4 TLS fingerprinting for C2
- Network flow analysis
- Temporal pattern detection
- Custom signature support
- YARA rule integration

## References

- MITRE ATT&CK: Command and Control (TA0011)
- MITRE ATT&CK: Exfiltration Over C2 Channel (T1041)
- MITRE ATT&CK: DNS Tunneling (T1071.004)
- Cobalt Strike Malleable C2 Profiles
- Metasploit Framework Documentation
- DNS Tunneling Detection Techniques

## Author
Krishnendu Paul (@bidhata)
https://krishnendu.com
https://github.com/bidhata/PCaptor
