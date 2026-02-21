# C2 Detection Quick Reference

## Supported C2 Frameworks (11 Total)

| Framework | Confidence | Key Indicators |
|-----------|-----------|----------------|
| **Cobalt Strike** | High | 40+ URIs, jQuery patterns, checksum8 |
| **Metasploit** | High | Meterpreter, payload checksums |
| **PowerShell Empire** | High | /admin/get.php, /news.php |
| **Covenant** | Medium | /covenant patterns |
| **Sliver** | Medium | High entropy URIs, /stage |
| **Mythic** | High | /api/v1.4/, /agent_message |
| **Brute Ratel C4** | High | Badger UA, /c4/ |
| **PoshC2** | Medium-High | /implant, /posh |
| **Havoc** | Medium | /demon, /listener |
| **Pupy RAT** | High | /pupy, pupy UA |
| **Koadic** | Medium | /koadic, /stager |

## Detection Methods

### 1. Signature-Based
- Framework-specific URIs
- User-Agent patterns
- Known tool signatures

### 2. Behavioral Analysis
- Non-browser User-Agents
- High entropy URIs (>60% unique chars)
- Direct IP communication
- Non-standard ports (4444, 8080, 8443, etc.)
- Suspicious script parameters

### 3. DNS Tunneling
- Long subdomains (>50 chars)
- High entropy subdomains
- Excessive levels (>5)
- Known tools (dnscat, iodine, dns2tcp)
- Encoded data (Base32/Base64)

### 4. Generic Patterns
- Suspicious keywords (/c2/, /command, /backdoor)
- Base64 encoding (>80% match)
- URL encoding (>5 %)
- UUID patterns

## Confidence Levels

| Level | Badge | Criteria |
|-------|-------|----------|
| **High** | 🔴 Red | Multiple indicators, known signatures |
| **Medium** | 🟡 Yellow | Single strong indicator, entropy patterns |
| **Low** | 🔵 Blue | Generic patterns, behavioral anomalies |

## Command Usage

```bash
# HTML report with C2 detection
./easypcap -f capture.pcap -html

# CSV export for SIEM
./easypcap -f capture.pcap -csv

# JSON for automation
./easypcap -f capture.pcap -json

# All formats
./easypcap -f capture.pcap -html -csv -json
```

## Output Files

| File | Content |
|------|---------|
| `*_report.html` | Interactive report with C2 Detection tab |
| `*_c2_detections.csv` | All C2 detections in CSV format |
| `*_report.json` | Complete data in JSON (c2_detections key) |

## CSV Format

```csv
Timestamp,Framework,Indicator,Confidence,Detail,URL,Source IP,Destination IP
2026-01-01 05:45:12,Cobalt Strike,Default URI: /beacon,high,Detected CS pattern,http://...,10.0.0.1,192.168.1.1
```

## Common Patterns

### Cobalt Strike
```
/activity, /beacon, /ga.js, /__utm.gif
/jquery-*.min.js, /functionalscript/
```

### Metasploit
```
/msf, /meterpreter, /payload
/abcdefghijklmnopqrstuvwxyz
```

### DNS Tunneling
```
aGVsbG93b3JsZGhlbGxvd29ybGQ.example.com (long)
x7k9m2p4q8r1s5t3.example.com (high entropy)
a.b.c.d.e.f.example.com (excessive levels)
```

## Quick Checks

### High Priority (Investigate Immediately)
- High confidence detections
- Known C2 framework matches
- DNS tunneling with long subdomains
- Multiple detections from same IP

### Medium Priority (Review)
- Medium confidence detections
- Behavioral anomalies
- Non-standard ports
- High entropy patterns

### Low Priority (Monitor)
- Low confidence detections
- Generic patterns
- Single behavioral indicator

## Integration Examples

### Splunk
```bash
./easypcap -f capture.pcap -csv
splunk add oneshot capture_c2_detections.csv -sourcetype csv
```

### ELK Stack
```bash
./easypcap -f capture.pcap -json
curl -X POST "localhost:9200/c2/_doc" -H 'Content-Type: application/json' -d @capture_report.json
```

### Python
```python
import json
with open('capture_report.json') as f:
    data = json.load(f)
    for c2 in data['c2_detections']:
        if c2['confidence'] == 'high':
            print(f"Alert: {c2['framework']} - {c2['url']}")
```

## Performance

| Metric | Value |
|--------|-------|
| Processing Speed | ~75K packets/second |
| Memory Usage | Capped at 8GB for large files |
| Max Detections | 100K per protocol |
| Max Flows | 1M flows |

## Troubleshooting

### No Detections
- Check if HTTP/DNS traffic exists
- Verify PCAP file is valid
- Look for encrypted traffic (HTTPS)

### Too Many Detections
- Filter by confidence level (high only)
- Review behavioral patterns
- Adjust thresholds if needed

### Performance Issues
- Use `-w` flag to adjust workers
- Process smaller time windows
- Increase system resources

## References

- Full Documentation: `C2_DETECTION.md`
- Technical Details: `C2_ENHANCEMENT_SUMMARY.md`
- Complete Guide: `FINAL_C2_ENHANCEMENT.md`

## Author
Krishnendu Paul (@bidhata)  
https://github.com/bidhata/PCaptor
