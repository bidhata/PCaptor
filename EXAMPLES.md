# EasyPCAP Examples

This document provides practical examples of using EasyPCAP for various scenarios.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Advanced Analysis](#advanced-analysis)
- [SIEM Integration](#siem-integration)
- [Automation](#automation)
- [Incident Response](#incident-response)
- [Threat Hunting](#threat-hunting)

---

## Basic Usage

### Example 1: Quick Analysis

Analyze a PCAP file and generate an HTML report:

```bash
# Windows
easypcap-windows-amd64.exe -f capture.pcap -html

# Linux
./easypcap-linux-amd64 -f capture.pcap -html
```

**Output:**
- `capture_report.html` - Interactive dashboard
- `capture_extracted/` - Extracted files and certificates

### Example 2: Complete Export

Generate all report formats:

```bash
./easypcap -f network_traffic.pcap -html -csv -json
```

**Output:**
- HTML report with interactive dashboard
- 11 CSV files for SIEM integration
- JSON file for automation

### Example 3: Custom Output Directory

Specify where to save results:

```bash
./easypcap -f capture.pcap -o /analysis/results -html -csv
```

### Example 4: Performance Tuning

Adjust worker count for better performance:

```bash
# Use 32 workers for large files
./easypcap -f large_capture.pcap -w 32 -html

# Use fewer workers on limited systems
./easypcap -f capture.pcap -w 8 -html
```

---

## Advanced Analysis

### Example 5: C2 Detection Focus

Analyze specifically for C2 communications:

```bash
# Generate report and review C2 Detection tab
./easypcap -f suspicious.pcap -html -csv

# Extract only C2 detections
cat suspicious_c2_detections.csv | grep "high" > high_confidence_c2.csv
```

### Example 6: Credential Extraction

Focus on extracted credentials:

```bash
./easypcap -f capture.pcap -csv

# Review credentials
cat capture_credentials.csv | column -t -s,

# Filter weak passwords
awk -F',' '$7 < 50' capture_credentials.csv
```

### Example 7: Protocol Analysis

Analyze specific protocols:

```bash
./easypcap -f capture.pcap -csv

# Review IRC chat
cat capture_irc_chat.csv

# Review SNMP messages
cat capture_snmp.csv

# Review SIP calls
cat capture_sip.csv
```

### Example 8: DNS Tunneling Detection

Look for DNS tunneling attempts:

```bash
./easypcap -f capture.pcap -html -csv

# Filter DNS tunneling detections
grep "DNS Tunneling" capture_c2_detections.csv
```

---

## SIEM Integration

### Example 9: Splunk Integration

```bash
# Generate CSV files
./easypcap -f capture.pcap -csv

# Import to Splunk
splunk add oneshot capture_threats.csv -sourcetype csv -index security
splunk add oneshot capture_c2_detections.csv -sourcetype csv -index security
splunk add oneshot capture_http_urls.csv -sourcetype csv -index security
```

### Example 10: ELK Stack Integration

```bash
# Generate JSON
./easypcap -f capture.pcap -json

# Import to Elasticsearch
curl -X POST "localhost:9200/easypcap/_doc" \
  -H 'Content-Type: application/json' \
  -d @capture_report.json
```

### Example 11: QRadar Integration

```bash
# Generate CSV files
./easypcap -f capture.pcap -csv

# Configure QRadar log source to read CSV files
# Import via QRadar Admin Console
```

---

## Automation

### Example 12: Batch Processing (Bash)

```bash
#!/bin/bash
# Process all PCAP files in a directory

PCAP_DIR="/captures"
OUTPUT_DIR="/analysis"

for pcap in "$PCAP_DIR"/*.pcap; do
    echo "Processing: $pcap"
    ./easypcap -f "$pcap" -o "$OUTPUT_DIR" -html -csv -json
done

echo "Batch processing complete!"
```

### Example 13: Automated Analysis (Python)

```python
#!/usr/bin/env python3
import os
import subprocess
import json
from datetime import datetime

def analyze_pcap(pcap_file):
    """Analyze PCAP file and return results"""
    print(f"Analyzing: {pcap_file}")
    
    # Run EasyPCAP
    subprocess.run([
        './easypcap',
        '-f', pcap_file,
        '-json'
    ])
    
    # Load results
    json_file = pcap_file.replace('.pcap', '_report.json')
    with open(json_file) as f:
        return json.load(f)

def alert_on_threats(data):
    """Send alerts for high-confidence threats"""
    for detection in data.get('c2_detections', []):
        if detection['confidence'] == 'high':
            print(f"🚨 ALERT: {detection['framework']} detected!")
            print(f"   URL: {detection['url']}")
            print(f"   Source: {detection['SrcIP']}")
            print(f"   Destination: {detection['DstIP']}")
            # Send to alerting system
            # send_alert(detection)

def main():
    pcap_dir = '/captures'
    
    for filename in os.listdir(pcap_dir):
        if filename.endswith('.pcap'):
            pcap_path = os.path.join(pcap_dir, filename)
            data = analyze_pcap(pcap_path)
            alert_on_threats(data)

if __name__ == '__main__':
    main()
```

### Example 14: Scheduled Analysis (Cron)

```bash
# Add to crontab
# Analyze new captures every hour
0 * * * * /usr/local/bin/easypcap -f /captures/latest.pcap -html -csv

# Daily summary report
0 0 * * * /scripts/daily_analysis.sh
```

---

## Incident Response

### Example 15: Rapid Triage

```bash
# Quick analysis for incident response
./easypcap -f incident.pcap -html

# Open HTML report in browser
# Review Dashboard for overview
# Check Threats tab for security issues
# Review C2 Detection tab for command & control
```

### Example 16: IOC Extraction

```bash
# Generate all reports
./easypcap -f incident.pcap -csv

# Extract IOCs
echo "=== Malicious IPs ===" > iocs.txt
awk -F',' 'NR>1 {print $7}' incident_c2_detections.csv | sort -u >> iocs.txt

echo "=== Malicious URLs ===" >> iocs.txt
awk -F',' 'NR>1 {print $6}' incident_c2_detections.csv | sort -u >> iocs.txt

echo "=== Suspicious Domains ===" >> iocs.txt
awk -F',' 'NR>1 {print $4}' incident_threats.csv | grep -E '\.' | sort -u >> iocs.txt
```

### Example 17: Timeline Reconstruction

```bash
# Generate CSV with timestamps
./easypcap -f incident.pcap -csv

# Create timeline
cat incident_c2_detections.csv | sort -t',' -k1 > timeline.csv
cat incident_threats.csv | sort -t',' -k1 >> timeline.csv
```

---

## Threat Hunting

### Example 18: Hunt for Specific C2

```bash
# Analyze traffic
./easypcap -f capture.pcap -csv

# Hunt for Cobalt Strike
grep "Cobalt Strike" capture_c2_detections.csv

# Hunt for Metasploit
grep "Metasploit" capture_c2_detections.csv

# Hunt for DNS tunneling
grep "DNS Tunneling" capture_c2_detections.csv
```

### Example 19: Behavioral Analysis

```bash
# Look for behavioral indicators
./easypcap -f capture.pcap -csv

# Non-browser User-Agents
grep "Behavioral" capture_c2_detections.csv | grep "User-Agent"

# Direct IP communication
grep "Direct IP" capture_c2_detections.csv

# High entropy URIs
grep "entropy" capture_c2_detections.csv
```

### Example 20: Credential Compromise

```bash
# Extract all credentials
./easypcap -f capture.pcap -csv

# Review cleartext credentials
cat capture_credentials.csv

# Find weak passwords
awk -F',' '$7 < 30 {print $0}' capture_credentials.csv
```

---

## Performance Examples

### Example 21: Large File Analysis

```bash
# Analyze 5GB PCAP file
./easypcap -f large_capture.pcap -w 32 -html

# Monitor progress
# Processing speed: ~75K packets/second
# Memory usage: Capped at 8GB
# Flow limit: 1M flows
```

### Example 22: Memory-Constrained System

```bash
# Reduce workers for limited memory
./easypcap -f capture.pcap -w 4 -html

# Process in chunks if needed
tcpdump -r large.pcap -w chunk1.pcap -c 100000
./easypcap -f chunk1.pcap -html
```

---

## Integration Examples

### Example 23: REST API Integration

```python
import requests
import subprocess
import json

def analyze_and_send(pcap_file, api_url):
    # Run analysis
    subprocess.run(['./easypcap', '-f', pcap_file, '-json'])
    
    # Load results
    with open(f'{pcap_file.replace(".pcap", "")}_report.json') as f:
        data = json.load(f)
    
    # Send to API
    response = requests.post(api_url, json=data)
    return response.json()

# Usage
result = analyze_and_send('capture.pcap', 'https://api.example.com/analysis')
```

### Example 24: Webhook Notifications

```bash
#!/bin/bash
# Analyze and send webhook notification

./easypcap -f capture.pcap -json

# Extract summary
THREATS=$(jq '.threats | length' capture_report.json)
C2=$(jq '.c2_detections | length' capture_report.json)

# Send webhook
curl -X POST https://hooks.example.com/webhook \
  -H 'Content-Type: application/json' \
  -d "{\"threats\": $THREATS, \"c2_detections\": $C2}"
```

---

## Tips & Tricks

### Tip 1: Filter High-Confidence Detections

```bash
# Only show high-confidence C2 detections
awk -F',' '$4 == "high"' capture_c2_detections.csv
```

### Tip 2: Export Specific Protocols

```bash
# Only analyze HTTP traffic
./easypcap -f capture.pcap -csv
cat capture_http_urls.csv
```

### Tip 3: Compare Multiple Captures

```bash
# Analyze multiple files
for f in *.pcap; do
    ./easypcap -f "$f" -csv
    echo "$f: $(wc -l < ${f%.pcap}_c2_detections.csv) C2 detections"
done
```

### Tip 4: Generate Summary Report

```bash
#!/bin/bash
# Create summary from multiple analyses

echo "=== EasyPCAP Analysis Summary ===" > summary.txt
echo "Date: $(date)" >> summary.txt
echo "" >> summary.txt

for pcap in *.pcap; do
    echo "File: $pcap" >> summary.txt
    ./easypcap -f "$pcap" -json
    
    json="${pcap%.pcap}_report.json"
    echo "  Threats: $(jq '.threats | length' $json)" >> summary.txt
    echo "  C2 Detections: $(jq '.c2_detections | length' $json)" >> summary.txt
    echo "" >> summary.txt
done
```

---

## Sample PCAP Files

For testing, you can use:
- **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
- **PCAP Repository**: https://www.netresec.com/index.ashx?page=PcapFiles
- **Malware Traffic Analysis**: https://www.malware-traffic-analysis.net/

---

## Getting Help

- **Documentation**: [README.md](README.md)
- **C2 Detection**: [C2_DETECTION.md](C2_DETECTION.md)
- **Quick Reference**: [C2_QUICK_REFERENCE.md](C2_QUICK_REFERENCE.md)
- **Issues**: https://github.com/bidhata/PCaptor/issues

---

**Author**: Krishnendu Paul (@bidhata)  
**Website**: https://krishnendu.com  
**GitHub**: https://github.com/bidhata/PCaptor
