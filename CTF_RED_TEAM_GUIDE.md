# 🎯 CTF, Red Teaming & Threat Hunting Guide

## Overview

EasyPCAP v2.0+ includes advanced detection capabilities specifically designed for CTF challenges, Red Team operations, and Threat Hunting scenarios. This guide covers all the enhanced features and how to use them effectively.

---

## 🚀 New Detection Capabilities

### 1. Beaconing Detection

**What it detects**: Regular C2 callback patterns with statistical analysis

**How it works**:
- Analyzes packet timing intervals
- Calculates jitter (coefficient of variation)
- Low jitter (<0.3) = High confidence beaconing
- Identifies heartbeat communications

**Use Cases**:
- CTF: Find hidden C2 channels
- Red Team: Validate your beacon configuration
- Threat Hunting: Identify persistent threats

**Example Output**:
```
Beaconing detected: 192.168.1.100 -> 10.0.0.5:443
Interval: 60s, Jitter: 0.12, Packets: 150
Confidence: HIGH
```

**CSV Export**: `capture_beaconing.csv`

---

### 2. TLS Fingerprinting (JA3/JA4)

**What it detects**: Encrypted C2 communications via TLS fingerprints

**Known Malicious JA3 Hashes**:
- `6734f37431670b3ab4292b8f60f29984` - Cobalt Strike
- `a0e9f5d64349fb13191bc781f81f42e1` - Metasploit
- `72a589da586844d7f0818ce684948eea` - Sliver
- `51c64c77e60f3980eea90869b68c58a8` - Trickbot
- `e7d705a3286e19ea42f587b344ee6865` - Dridex
- And more...

**Use Cases**:
- CTF: Identify encrypted C2 even when you can't decrypt
- Red Team: Check if your C2 profile is fingerprinted
- Threat Hunting: Find known malware families

**CSV Export**: `capture_tls_fingerprints.csv`

---

### 3. SSH Tunneling Detection

**What it detects**: SSH tunnels used for pivoting or data exfiltration

**Detection Criteria**:
- High throughput (>100KB/s)
- High packet rate (>50 pkt/s)
- Long-lived connections (>1 hour)
- Unusual traffic patterns

**Use Cases**:
- CTF: Find SSH tunnels in network captures
- Red Team: Test your tunnel detection evasion
- Threat Hunting: Identify lateral movement via SSH

**Example**:
```
SSH Tunnel: 192.168.1.50 -> 10.0.0.20:22
Throughput: 250 KB/s, Duration: 3600s
Reason: High throughput + Long-lived connection
Confidence: HIGH
```

**CSV Export**: `capture_ssh_tunnels.csv`

---

### 4. ICMP Tunneling Detection

**What it detects**: Data hidden in ICMP packets

**Detection Methods**:
- Large ICMP payloads (>100 bytes)
- High entropy payloads (>0.7)
- Unusual ICMP patterns

**Use Cases**:
- CTF: Common covert channel technique
- Red Team: Test ICMP exfiltration
- Threat Hunting: Catch data exfiltration

**Tools Detected**:
- ptunnel
- icmptunnel
- Hans
- Custom ICMP tunnels

---

### 5. Lateral Movement Detection

**What it detects**: Attackers moving between systems

**Protocols Monitored**:
- **SMB (445)**: PsExec, WMI, DCOM
- **RDP (3389)**: Remote Desktop
- **SSH (22)**: SSH lateral movement
- **WinRM (5985/5986)**: PowerShell Remoting
- **RPC (135)**: DCOM lateral movement
- **Databases**: MSSQL, MySQL, PostgreSQL

**Detection Logic**:
- Source IP connecting to 3+ targets on same port = LOW confidence
- Source IP connecting to 5+ targets = MEDIUM confidence
- Source IP connecting to 10+ targets = HIGH confidence

**Use Cases**:
- CTF: Identify attack paths
- Red Team: Validate lateral movement techniques
- Threat Hunting: Map attacker movement

**Example**:
```
Lateral Movement: 192.168.1.100 -> 15 targets on port 445
Technique: SMB lateral movement (PsExec/WMI/DCOM)
Targets: 192.168.1.10, 192.168.1.11, 192.168.1.12, ...
Confidence: HIGH
```

**CSV Export**: `capture_lateral_movement.csv`

---

### 6. Data Exfiltration Detection

**What it detects**: Large data uploads indicating exfiltration

**Detection Criteria**:
- Upload rate >50KB/s sustained
- Large total transfers (>10MB = higher confidence)

**Methods Detected**:
- HTTP/HTTPS POST exfiltration
- FTP uploads
- SSH/SCP transfers
- DNS tunneling
- SMTP email exfiltration
- SMB file transfers

**Use Cases**:
- CTF: Find the exfiltration method
- Red Team: Test exfiltration detection
- Threat Hunting: Identify data theft

**Example**:
```
Data Exfiltration: 192.168.1.100 -> 10.0.0.50:443
Method: HTTPS exfiltration
Transferred: 50.2 MB at 125 KB/s over 6m40s
Confidence: HIGH
```

**CSV Export**: `capture_exfiltration.csv`

---

### 7. Steganography Detection

**What it detects**: Hidden data in images and files

**Detection Methods**:
- LSB (Least Significant Bit) entropy analysis
- Known tool signatures
- Metadata entropy analysis

**Tools Detected**:
- Steghide
- OutGuess
- JPHide
- JSteg
- F5 Algorithm
- OpenStego

**File Types Analyzed**:
- PNG, JPEG, BMP, GIF images
- PDF documents
- ZIP/RAR archives

**Use Cases**:
- CTF: Very common challenge technique
- Red Team: Test stego detection
- Threat Hunting: Find hidden communications

---

### 8. Cryptocurrency Mining Detection

**What it detects**: Unauthorized crypto mining activity

**Detection Methods**:
- 50+ known mining pools
- Stratum protocol detection
- Mining software signatures
- Common mining ports (3333, 4444, 5555, etc.)

**Mining Software Detected**:
- XMRig
- XMR-Stak
- Claymore
- PhoenixMiner
- CGMiner
- CCMiner

**Use Cases**:
- CTF: Find cryptojacking
- Red Team: Test mining detection
- Threat Hunting: Identify resource abuse

---

### 9. Anonymization Detection

**What it detects**: Tor, VPN, and proxy usage

**Detection Methods**:
- Tor ports (9001, 9030, 9050, 9051, 9150)
- VPN protocols (OpenVPN, PPTP, IPSec, L2TP)
- VPN providers (NordVPN, ExpressVPN, ProtonVPN, etc.)
- .onion domains
- SOCKS4/5 proxies

**Use Cases**:
- CTF: Identify anonymization attempts
- Red Team: Test anonymization detection
- Threat Hunting: Find hidden communications

---

### 10. Payload Entropy Analysis

**What it detects**: Encrypted or packed payloads

**Detection Logic**:
- Entropy >0.9 = Suspicious
- Entropy >0.95 = Almost certainly encrypted
- Minimum payload size: 100 bytes

**Use Cases**:
- CTF: Identify encrypted communications
- Red Team: Test payload obfuscation
- Threat Hunting: Find encrypted C2

---

## 📊 CTF Workflow

### Step 1: Initial Analysis
```bash
./easypcap -f challenge.pcap -html -csv -json
```

### Step 2: Review HTML Report
- Check Dashboard for threat score
- Review C2 Detections section
- Look for beaconing patterns
- Check lateral movement

### Step 3: Deep Dive with CSV
```bash
# Check for beaconing
cat challenge_beaconing.csv | grep "high"

# Look for exfiltration
cat challenge_exfiltration.csv

# Find lateral movement
cat challenge_lateral_movement.csv

# Check TLS fingerprints
cat challenge_tls_fingerprints.csv
```

### Step 4: Correlate Findings
- Match beaconing with C2 detections
- Correlate lateral movement with exfiltration
- Check timing of events

---

## 🔴 Red Team Validation

### Test Your C2 Configuration

1. **Capture your C2 traffic**:
```bash
tcpdump -i eth0 -w my_c2.pcap
```

2. **Analyze with EasyPCAP**:
```bash
./easypcap -f my_c2.pcap -html
```

3. **Check detections**:
- Is your C2 framework detected?
- Is beaconing identified?
- Is your JA3 fingerprint flagged?
- Are tunnels detected?

4. **Improve your OPSEC**:
- Adjust beacon jitter
- Use custom TLS profiles
- Randomize timing
- Use domain fronting

---

## 🎯 Threat Hunting Scenarios

### Scenario 1: APT Investigation

**Goal**: Find persistent threat in 30-day capture

**Steps**:
1. Look for beaconing patterns (regular callbacks)
2. Check for lateral movement (multiple targets)
3. Identify exfiltration (large uploads)
4. Correlate with C2 detections

**Commands**:
```bash
./easypcap -f 30day_capture.pcap -csv
grep "high" *_beaconing.csv
grep "high" *_lateral_movement.csv
grep "high" *_exfiltration.csv
```

### Scenario 2: Insider Threat

**Goal**: Detect data theft by employee

**Look for**:
- Large uploads to external IPs
- SSH/SCP transfers
- Email exfiltration
- Cloud storage uploads

**Commands**:
```bash
./easypcap -f employee_traffic.pcap -csv
cat *_exfiltration.csv | sort -t',' -k5 -rn
```

### Scenario 3: Ransomware Investigation

**Goal**: Identify ransomware C2 and lateral movement

**Look for**:
- C2 beaconing
- SMB lateral movement (port 445)
- Crypto mining (some ransomware mines)
- TLS fingerprints

**Commands**:
```bash
./easypcap -f ransomware.pcap -html -csv
grep "445" *_lateral_movement.csv
grep "Cobalt Strike\|Metasploit" *_c2_detections.csv
```

---

## 🛠️ Advanced Techniques

### Combine with Other Tools

#### With Wireshark
```bash
# Generate report
./easypcap -f capture.pcap -csv

# Open suspicious flows in Wireshark
wireshark -r capture.pcap -Y "ip.addr == 10.0.0.5 and tcp.port == 443"
```

#### With Zeek/Bro
```bash
# Run both tools
zeek -r capture.pcap
./easypcap -f capture.pcap -csv

# Compare findings
diff zeek_conn.log capture_flows.csv
```

#### With Suricata
```bash
# Run Suricata
suricata -r capture.pcap -l logs/

# Run EasyPCAP
./easypcap -f capture.pcap -csv

# Correlate alerts
```

### Automation Scripts

#### Batch Analysis
```bash
#!/bin/bash
for pcap in /captures/*.pcap; do
    echo "Analyzing $pcap..."
    ./easypcap -f "$pcap" -csv -json
    
    # Check for high-confidence threats
    if grep -q "high" "${pcap%.pcap}_beaconing.csv" 2>/dev/null; then
        echo "⚠️  ALERT: Beaconing detected in $pcap"
    fi
done
```

#### Threat Score Monitoring
```python
import json
import sys

with open('capture_report.json') as f:
    data = json.load(f)
    
threat_score = data['statistics']['ThreatScore']

if threat_score > 80:
    print(f"🚨 CRITICAL: Threat score {threat_score}")
    sys.exit(1)
elif threat_score > 50:
    print(f"⚠️  WARNING: Threat score {threat_score}")
    sys.exit(0)
else:
    print(f"✅ OK: Threat score {threat_score}")
    sys.exit(0)
```

---

## 📈 Performance Tips

### Large Captures (>1GB)

1. **Increase workers**:
```bash
./easypcap -f large.pcap -w 32 -html
```

2. **Use CSV only** (faster):
```bash
./easypcap -f large.pcap -csv
```

3. **Split captures**:
```bash
tcpdump -r large.pcap -w split -C 500
./easypcap -f split* -csv
```

### Memory Optimization

- Flow limit: 1,000,000 flows
- Message limit: 100,000 per protocol
- Memory cap: ~8GB for large files

---

## 🎓 Learning Resources

### CTF Challenges

Practice with these PCAP challenges:
- **Malware-Traffic-Analysis.net**: Real malware PCAPs
- **CTFtime.org**: Search for "pcap" challenges
- **CyberDefenders**: Blue team challenges
- **SANS NetWars**: Network forensics

### Red Team Resources

- **Cobalt Strike**: Test C2 detection
- **Metasploit**: Meterpreter traffic analysis
- **Empire**: PowerShell C2 patterns
- **Sliver**: Modern C2 framework

### Threat Hunting

- **MITRE ATT&CK**: Technique mapping
- **Cyber Kill Chain**: Attack phases
- **Diamond Model**: Threat intelligence
- **ThreatHunter-Playbook**: Hunting scenarios

---

## 🔍 Detection Evasion (Red Team)

### Evade Beaconing Detection

1. **Add jitter** (>30%):
```python
import random
import time

interval = 60  # base interval
jitter = 0.4   # 40% jitter

while True:
    sleep_time = interval * (1 + random.uniform(-jitter, jitter))
    time.sleep(sleep_time)
    beacon()
```

2. **Randomize intervals**:
```python
intervals = [30, 45, 60, 90, 120]
time.sleep(random.choice(intervals))
```

### Evade TLS Fingerprinting

1. **Use custom TLS profiles**
2. **Rotate JA3 fingerprints**
3. **Mimic legitimate applications**
4. **Use domain fronting**

### Evade Lateral Movement Detection

1. **Slow down** (fewer targets per hour)
2. **Use different ports**
3. **Randomize timing**
4. **Use legitimate tools** (RDP, SSH)

---

## 📞 Support

For CTF/Red Team/Threat Hunting specific questions:
- GitHub Issues: https://github.com/bidhata/PCaptor/issues
- Email: contact@krishnendu.com

---

## 🏆 Credits

**Author**: Krishnendu Paul (@bidhata)
**Website**: https://krishnendu.com
**GitHub**: https://github.com/bidhata/PCaptor

---

**Happy Hunting! 🎯**
