package main

// engine.go — the DPI processing loop
//
// Engine.Run() is the heart of the system.  It:
//   1. Opens the input .pcap file
//   2. Creates the output .pcap file
//   3. Reads every packet in a loop
//   4. Parses the Ethernet/IP/TCP/UDP headers
//   5. Looks up (or creates) the flow entry for this five-tuple
//   6. Attempts SNI / HTTP Host / DNS extraction (Deep Packet Inspection)
//   7. Applies blocking rules
//   8. Writes allowed packets to the output file
//   9. Prints a summary report
//
// Flow tracking is the key to stateful blocking:
// Once we see a TLS Client Hello for "www.youtube.com" and mark the flow
// as BLOCKED, every subsequent packet of that same five-tuple is dropped
// immediately — no need to re-inspect each one.

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// ============================================================================
// Engine — the top-level DPI coordinator
// ============================================================================

// Engine holds configuration and runs the packet processing loop.
type Engine struct {
	InputFile  string
	OutputFile string
	Rules      *RuleManager

	// Internal state — populated during Run()
	flows    map[FiveTuple]*Flow   // flow table: five-tuple → connection state
	appStats map[AppType]uint64    // packet count per application type
	sniSeen  map[string]AppType    // unique SNIs detected in this capture
	stats    Stats
}

// Stats holds aggregate counters for the final report.
type Stats struct {
	TotalPackets uint64
	TotalBytes   uint64
	TCPPackets   uint64
	UDPPackets   uint64
	Forwarded    uint64
	Dropped      uint64
}

// NewEngine creates an Engine with empty state.
func NewEngine(input, output string, rules *RuleManager) *Engine {
	return &Engine{
		InputFile:  input,
		OutputFile: output,
		Rules:      rules,
		flows:      make(map[FiveTuple]*Flow),
		appStats:   make(map[AppType]uint64),
		sniSeen:    make(map[string]AppType),
	}
}

// ============================================================================
// Run — the main processing loop
// ============================================================================

// Run processes every packet in InputFile, writes allowed packets to
// OutputFile, and prints a final report.
func (e *Engine) Run() error {
	// ── Open input ─────────────────────────────────────────────────────────
	reader := &PcapReader{}
	if err := reader.Open(e.InputFile); err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer reader.Close()

	// ── Open output ─────────────────────────────────────────────────────────
	writer := &PcapWriter{}
	if err := writer.Create(e.OutputFile, reader.GlobalHdr); err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer writer.Close()

	printBanner()
	fmt.Println("[DPI] Processing packets...")

	// ── Packet loop ─────────────────────────────────────────────────────────
	for {
		raw, err := reader.ReadNext()
		if err == io.EOF {
			break // Normal end of capture
		}
		if err != nil {
			return fmt.Errorf("reading packet: %w", err)
		}

		// Process the packet and decide forward / drop.
		action := e.processPacket(raw)

		if action == "forward" {
			if err := writer.WritePacket(raw); err != nil {
				return fmt.Errorf("writing packet: %w", err)
			}
			e.stats.Forwarded++
		} else {
			e.stats.Dropped++
		}
	}

	// ── Report ─────────────────────────────────────────────────────────────
	e.printReport()
	fmt.Printf("\nOutput written to: %s\n", e.OutputFile)
	return nil
}

// ============================================================================
// processPacket — per-packet logic
//
// Returns "forward" or "drop".
//
// The function is intentionally kept as a single readable method rather than
// split across many helpers, so the decision flow is easy to follow.
// ============================================================================
func (e *Engine) processPacket(raw *RawPacket) string {
	// ── Parse headers ────────────────────────────────────────────────────────
	parsed, ok := ParsePacket(raw)
	if !ok || !parsed.HasIP || (!parsed.HasTCP && !parsed.HasUDP) {
		// Packets that fail parsing (ARP, IPv6, truncated, etc.) are forwarded
		// transparently — we don't want to accidentally drop control traffic.
		return "forward"
	}

	// ── Update aggregate counters ─────────────────────────────────────────
	e.stats.TotalPackets++
	e.stats.TotalBytes += uint64(len(raw.Data))
	if parsed.HasTCP {
		e.stats.TCPPackets++
	} else {
		e.stats.UDPPackets++
	}

	// ── Build five-tuple and look up flow ─────────────────────────────────
	//
	// The five-tuple is the unique key for a connection.  All packets of the
	// same TCP/UDP conversation share the same entry in e.flows.
	tuple := FiveTuple{
		SrcIP:    parsed.SrcIPRaw,
		DstIP:    parsed.DstIPRaw,
		SrcPort:  parsed.SrcPort,
		DstPort:  parsed.DstPort,
		Protocol: parsed.Protocol,
	}

	flow, exists := e.flows[tuple]
	if !exists {
		// First packet of this connection — create a new flow entry.
		flow = &Flow{Tuple: tuple}
		e.flows[tuple] = flow
	}
	flow.Packets++
	flow.Bytes += uint64(len(raw.Data))

	// ── Deep Packet Inspection ─────────────────────────────────────────────
	//
	// We only inspect the payload if we haven't already classified this flow.
	// The SNI only appears in the first packet (TLS Client Hello), so we stop
	// trying once we've found it or after the first few packets.

	if flow.SNI == "" && parsed.Payload != nil {
		e.classifyFlow(flow, parsed)
	}

	// ── Port-based fallback classification ───────────────────────────────
	//
	// If DPI didn't find an SNI, classify by port number.
	if flow.AppType == AppUnknown {
		switch {
		// UDP port 443 is QUIC — must be checked before the generic port-443 case
		// so that QUIC flows aren't misclassified as HTTPS (TCP).
		case (parsed.DstPort == 443 || parsed.SrcPort == 443) && parsed.HasUDP:
			flow.AppType = AppQUIC
		case parsed.DstPort == 443 || parsed.SrcPort == 443:
			flow.AppType = AppHTTPS
		case parsed.DstPort == 80 || parsed.SrcPort == 80:
			flow.AppType = AppHTTP
		case parsed.DstPort == 53 || parsed.SrcPort == 53:
			flow.AppType = AppDNS
		}
	}

	// ── Apply blocking rules ──────────────────────────────────────────────
	//
	// Only re-evaluate rules for flows not yet marked as blocked.
	// Once blocked, all future packets of this flow are dropped without
	// re-checking rules — this is the "flow-based blocking" model.
	if !flow.Blocked {
		reason := e.Rules.ShouldBlock(tuple.SrcIP, tuple.DstPort, flow.AppType, flow.SNI)
		if reason != nil {
			flow.Blocked = true
			fmt.Printf("[BLOCKED] %s → %s (%s %s)\n",
				parsed.SrcIP, parsed.DstIP,
				flow.AppType, reason)
		}
	}

	// ── Update app stats ─────────────────────────────────────────────────
	e.appStats[flow.AppType]++

	// ── Forward or drop ───────────────────────────────────────────────────
	if flow.Blocked {
		return "drop"
	}
	return "forward"
}

// ============================================================================
// classifyFlow — attempt to extract hostname from the packet payload
// ============================================================================

// classifyFlow runs the appropriate extractor based on port and protocol.
// It updates flow.SNI and flow.AppType on success.
func (e *Engine) classifyFlow(flow *Flow, parsed *ParsedPacket) {
	payload := parsed.Payload

	switch {
	// ── TLS / HTTPS (TCP port 443) ────────────────────────────────────────
	//
	// The TLS Client Hello arrives in the very first data packet of the
	// TCP connection (after the SYN / SYN-ACK / ACK handshake).
	// It carries the SNI extension in plaintext before encryption starts.
	case parsed.HasTCP && (parsed.DstPort == 443 || parsed.SrcPort == 443):
		if sni, ok := ExtractTLSSNI(payload); ok {
			flow.SNI = sni
			flow.AppType = SNIToAppType(sni)
			// Record this SNI in the global seen-map for the final report.
			e.sniSeen[sni] = flow.AppType
		}

	// ── Plain HTTP (TCP port 80) ──────────────────────────────────────────
	//
	// HTTP/1.x requests contain a "Host:" header we can read directly.
	case parsed.HasTCP && (parsed.DstPort == 80 || parsed.SrcPort == 80):
		if host, ok := ExtractHTTPHost(payload); ok {
			flow.SNI = host
			flow.AppType = SNIToAppType(host)
			e.sniSeen[host] = flow.AppType
		}

	// ── DNS (UDP port 53) ─────────────────────────────────────────────────
	//
	// DNS is useful for logging which domains are being resolved,
	// even though we classify the flow simply as AppDNS.
	case parsed.DstPort == 53 || parsed.SrcPort == 53:
		if domain, ok := ExtractDNSQuery(payload); ok {
			flow.SNI = domain // Repurpose SNI field to store DNS query name
			flow.AppType = AppDNS
		}
	}
}

// ============================================================================
// printReport — formatted summary printed after all packets are processed
// ============================================================================

func (e *Engine) printReport() {
	total := e.stats.TotalPackets
	if total == 0 {
		total = 1 // Avoid division by zero for percentage calculations
	}

	sep := strings.Repeat("═", 62)
	fmt.Printf("\n╔%s╗\n", sep)
	fmt.Printf("║%s║\n", centre("PROCESSING REPORT", 62))
	fmt.Printf("╠%s╣\n", sep)
	fmt.Printf("║  Total Packets:  %10d                                  ║\n", e.stats.TotalPackets)
	fmt.Printf("║  Total Bytes:    %10d                                  ║\n", e.stats.TotalBytes)
	fmt.Printf("║  TCP Packets:    %10d                                  ║\n", e.stats.TCPPackets)
	fmt.Printf("║  UDP Packets:    %10d                                  ║\n", e.stats.UDPPackets)
	fmt.Printf("╠%s╣\n", sep)
	fmt.Printf("║  Forwarded:      %10d                                  ║\n", e.stats.Forwarded)
	fmt.Printf("║  Dropped:        %10d                                  ║\n", e.stats.Dropped)
	fmt.Printf("║  Active Flows:   %10d                                  ║\n", len(e.flows))
	fmt.Printf("╠%s╣\n", sep)
	fmt.Printf("║%s║\n", centre("APPLICATION BREAKDOWN", 62))
	fmt.Printf("╠%s╣\n", sep)

	// Sort apps by packet count descending so the busiest appear first.
	type appCount struct {
		app   AppType
		count uint64
	}
	var sorted []appCount
	for app, count := range e.appStats {
		sorted = append(sorted, appCount{app, count})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	for _, ac := range sorted {
		pct := float64(ac.count) * 100.0 / float64(total)
		barLen := int(pct / 4) // Each '#' represents ~4%
		bar := strings.Repeat("#", barLen)
		blocked := ""
		if e.Rules.IsAppBlocked(ac.app) {
			blocked = " (BLOCKED)"
		}
		fmt.Printf("║  %-15s %7d  %5.1f%%  %-20s%s\n",
			ac.app.String(), ac.count, pct, bar, blocked)
	}

	fmt.Printf("╚%s╝\n", sep)

	// List unique detected hostnames
	if len(e.sniSeen) > 0 {
		fmt.Println("\n[Detected Domains / SNIs]")
		// Sort for deterministic output
		var snisSlice []string
		for sni := range e.sniSeen {
			snisSlice = append(snisSlice, sni)
		}
		sort.Strings(snisSlice)
		for _, sni := range snisSlice {
			fmt.Printf("  - %s → %s\n", sni, e.sniSeen[sni])
		}
	}
}

// ============================================================================
// Formatting helpers
// ============================================================================

func printBanner() {
	sep := strings.Repeat("═", 62)
	fmt.Printf("╔%s╗\n", sep)
	fmt.Printf("║%s║\n", centre("DPI ENGINE v2.0 (Go port)", 62))
	fmt.Printf("╚%s╝\n\n", sep)
}

// centre pads s with spaces so it is exactly width chars wide.
func centre(s string, width int) string {
	total := width - len(s)
	if total <= 0 {
		return s
	}
	left := total / 2
	right := total - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}
