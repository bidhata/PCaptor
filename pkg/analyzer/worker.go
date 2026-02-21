package analyzer

import (
	"time"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (a *Analyzer) worker(packets <-chan gopacket.Packet) {
	defer a.wg.Done()
	
	// Local counters to reduce lock contention
	localProcessed := int64(0)

	for packet := range packets {
		a.processPacket(packet)
		localProcessed++
		
		// Batch update every 1000 packets to reduce lock contention
		if localProcessed%1000 == 0 {
			a.mu.Lock()
			a.processed += localProcessed
			a.mu.Unlock()
			localProcessed = 0
		}
	}
	
	// Final update
	if localProcessed > 0 {
		a.mu.Lock()
		a.processed += localProcessed
		a.mu.Unlock()
	}
}

func (a *Analyzer) processPacket(packet gopacket.Packet) {
	// Extract packet info
	info := PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    packet.Metadata().Length,
	}

	// Fast path: Parse layers efficiently
	var hasPayload bool
	var payloadData []byte
	
	// Parse IP layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.NextHeader.String()
	}

	// Only process if we have IP info
	if info.SrcIP == "" {
		return
	}

	// Parse TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = uint16(tcp.SrcPort)
		info.DstPort = uint16(tcp.DstPort)
		info.Protocol = "TCP"

		// Update flow
		a.updateFlow(info, int64(len(tcp.Payload)))

		// Only do deep inspection if there's payload
		if len(tcp.Payload) > 0 {
			hasPayload = true
			payloadData = tcp.Payload
			
			// Extract credentials and files from application layer
			a.extractFromTCP(tcp, info)
			
			// TLS fingerprinting
			a.parseTLS(tcp.Payload, info)
			
			// Stratum protocol detection (crypto mining)
			a.detectStratumProtocol(tcp.Payload, info)
			
			// SOCKS proxy detection
			a.detectSOCKSProxy(tcp.Payload, info)
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		// Parse UDP
		udp, _ := udpLayer.(*layers.UDP)
		info.SrcPort = uint16(udp.SrcPort)
		info.DstPort = uint16(udp.DstPort)
		info.Protocol = "UDP"

		// Update flow
		a.updateFlow(info, int64(len(udp.Payload)))

		// Parse DNS (only if it's likely DNS port)
		if udp.DstPort == 53 || udp.SrcPort == 53 {
			if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				a.parseDNS(dnsLayer.(*layers.DNS), info)
			}
		}

		// Extract from UDP protocols (only if payload exists)
		if len(udp.Payload) > 0 {
			hasPayload = true
			payloadData = udp.Payload
			a.extractFromUDP(udp, info)
		}
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		// Parse ICMP for tunneling detection
		icmp := icmpLayer.LayerContents()
		a.parseICMP(icmp, info)
	}
	
	// Payload entropy analysis (only for packets with significant payload)
	if hasPayload && len(payloadData) > 100 {
		a.analyzePayloadEntropy(payloadData, info)
	}

	// Don't store all packet info to save memory - only update counters
	// Batch update to reduce lock contention
	// This is now handled in worker() function
}

func (a *Analyzer) updateFlow(info PacketInfo, bytes int64) {
	key := FlowKey{
		SrcIP:   info.SrcIP,
		SrcPort: info.SrcPort,
		DstIP:   info.DstIP,
		DstPort: info.DstPort,
		Proto:   info.Protocol,
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Memory limit: stop tracking new flows if we exceed maxFlows
	if len(a.flows) >= a.maxFlows {
		// Only update existing flows
		if flow, exists := a.flows[key]; exists {
			flow.Packets++
			flow.Bytes += bytes
			flow.EndTime = info.Timestamp
			// Limit timestamps to prevent memory bloat - sample every 10th packet
			if len(flow.Timestamps) < 100 || flow.Packets%10 == 0 && len(flow.Timestamps) < 1000 {
				flow.Timestamps = append(flow.Timestamps, info.Timestamp)
			}
		}
		return
	}

	flow, exists := a.flows[key]
	if !exists {
		flow = &Flow{
			Key:       key,
			StartTime: info.Timestamp,
			Timestamps: make([]time.Time, 0, 100),
		}
		a.flows[key] = flow
	}

	flow.Packets++
	flow.Bytes += bytes
	flow.EndTime = info.Timestamp
	// Limit timestamps to prevent memory bloat - sample every 10th packet after 100
	if len(flow.Timestamps) < 100 || flow.Packets%10 == 0 && len(flow.Timestamps) < 1000 {
		flow.Timestamps = append(flow.Timestamps, info.Timestamp)
	}
}
