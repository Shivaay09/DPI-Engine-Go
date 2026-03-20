package main

// parser.go — layer-by-layer packet dissection
//
// Every captured Ethernet packet is structured like a set of nested envelopes:
//
//   ┌──────────────────────────────────────┐
//   │  Ethernet header  (14 bytes)         │  MAC src/dst, EtherType
//   │  ┌────────────────────────────────┐  │
//   │  │  IPv4 header  (20+ bytes)      │  │  IP src/dst, protocol
//   │  │  ┌──────────────────────────┐  │  │
//   │  │  │  TCP header (20+ bytes)  │  │  │  ports, flags, seq/ack
//   │  │  │  OR                      │  │  │
//   │  │  │  UDP header (8 bytes)    │  │  │
//   │  │  │  ─────────────────────── │  │  │
//   │  │  │  Payload (application)   │  │  │  TLS, HTTP, DNS …
//   │  │  └──────────────────────────┘  │  │
//   │  └────────────────────────────────┘  │
//   └──────────────────────────────────────┘
//
// We parse each layer in sequence, advancing an offset cursor.
// On any error (packet too short, wrong type) we return ok=false
// and the engine simply skips that packet.

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// EtherType constants (bytes 12-13 of the Ethernet header)
// ============================================================================
const (
	etherTypeIPv4 = 0x0800
)

// ============================================================================
// IP protocol numbers (byte 9 of the IPv4 header)
// ============================================================================
const (
	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

// ============================================================================
// TCP flag bitmasks (byte 13 of the TCP header)
// ============================================================================
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
	tcpFlagURG = 0x20
)

// ============================================================================
// ParsedPacket — result of successfully dissecting one raw captured packet
// ============================================================================

// ParsedPacket holds all fields extracted from a single captured packet.
// Fields are only valid if the corresponding Has* flag is true.
type ParsedPacket struct {
	// ── Layer 2 ──────────────────────────────────────────────────
	SrcMAC    string // "aa:bb:cc:dd:ee:ff"
	DstMAC    string
	EtherType uint16 // e.g. 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6
	HasEth    bool

	// ── Layer 3 ──────────────────────────────────────────────────
	SrcIP   string // dotted-decimal "192.168.1.1"
	DstIP   string
	SrcIPRaw uint32 // packed uint32 — same byte order as FiveTuple
	DstIPRaw uint32
	Protocol uint8  // 6=TCP, 17=UDP, etc.
	TTL     uint8
	HasIP   bool

	// ── Layer 4 ──────────────────────────────────────────────────
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32 // TCP sequence number
	AckNum   uint32 // TCP acknowledgment number
	TCPFlags uint8  // bitmask of TCP flag bits
	HasTCP   bool
	HasUDP   bool

	// ── Payload ──────────────────────────────────────────────────
	// Payload points into the original RawPacket.Data slice — no copy.
	// PayloadLen is the number of valid bytes starting at PayloadOffset.
	PayloadOffset int // byte offset into RawPacket.Data
	PayloadLen    int
	Payload       []byte // convenience slice of the payload bytes

	// ── Timestamps ───────────────────────────────────────────────
	TsSec  uint32
	TsUsec uint32
}

// ============================================================================
// ParsePacket — top-level entry point
//
// Given a RawPacket it calls the layer parsers in sequence.
// Returns (parsed, true) on success or (_, false) if the packet is
// too short or has an unexpected layer type.
// ============================================================================
func ParsePacket(raw *RawPacket) (*ParsedPacket, bool) {
	p := &ParsedPacket{
		TsSec:  raw.Header.TsSec,
		TsUsec: raw.Header.TsUsec,
	}
	data := raw.Data
	offset := 0

	// Layer 2: Ethernet
	ethOk, nextOffset := parseEthernet(data, offset, p)
	if !ethOk {
		return p, false
	}
	offset = nextOffset

	// Only handle IPv4 for now (EtherType 0x0800)
	if !p.HasEth {
		return p, false
	}

	// parseEthernet sets HasIP=false for non-IPv4 frames (ARP, IPv6, VLAN…).
	// Check it directly — do not use SrcIPRaw==0 as a sentinel because a
	// legitimate packet sourced from 0.0.0.0 would be incorrectly skipped.
	if !p.HasIP {
		return p, false
	}

	// Layer 3: IPv4
	ipOk, nextOffset := parseIPv4(data, offset, p)
	if !ipOk {
		return p, false
	}
	offset = nextOffset

	// Layer 4: TCP or UDP
	switch p.Protocol {
	case protoTCP:
		tcpOk, nextOffset := parseTCP(data, offset, p)
		if !tcpOk {
			return p, false
		}
		offset = nextOffset
	case protoUDP:
		udpOk, nextOffset := parseUDP(data, offset, p)
		if !udpOk {
			return p, false
		}
		offset = nextOffset
	default:
		// We don't parse ICMP etc. — but let the packet through for stats.
		return p, true
	}

	// Everything after the transport header is the payload.
	if offset < len(data) {
		p.PayloadOffset = offset
		p.PayloadLen = len(data) - offset
		p.Payload = data[offset:]
	}

	return p, true
}

// ============================================================================
// parseEthernet — Ethernet II header (14 bytes fixed)
//
//   Bytes  0– 5: Destination MAC
//   Bytes  6–11: Source MAC
//   Bytes 12–13: EtherType (big-endian)
// ============================================================================
func parseEthernet(data []byte, offset int, p *ParsedPacket) (bool, int) {
	const ethLen = 14
	if len(data) < offset+ethLen {
		return false, offset // Packet too short for Ethernet header
	}

	p.DstMAC = macToString(data[offset : offset+6])
	p.SrcMAC = macToString(data[offset+6 : offset+12])
	etherType := binary.BigEndian.Uint16(data[offset+12 : offset+14])
	p.EtherType = etherType // Store for downstream use / reporting
	p.HasEth = true

	if etherType != etherTypeIPv4 {
		// Not IPv4 (could be ARP, IPv6, VLAN…) — mark HasIP false and bail.
		p.HasIP = false
		// Return true for HasEth but set HasIP=false to signal skip.
		return true, offset + ethLen
	}

	// Signal to the caller that IPv4 follows.
	// We use HasIP as a pre-flag here; parseIPv4 will set it properly.
	p.HasIP = true
	return true, offset + ethLen
}

// ============================================================================
// parseIPv4 — IPv4 header (variable length, minimum 20 bytes)
//
//   Byte   0:    Version (4 bits, must be 4) + IHL (4 bits, header length / 4)
//   Byte   8:    TTL
//   Byte   9:    Protocol (6=TCP, 17=UDP)
//   Bytes 12–15: Source IP
//   Bytes 16–19: Destination IP
// ============================================================================
func parseIPv4(data []byte, offset int, p *ParsedPacket) (bool, int) {
	const minIPLen = 20
	if len(data) < offset+minIPLen {
		return false, offset
	}

	versionIHL := data[offset]
	version := (versionIHL >> 4) & 0x0F
	ihl := versionIHL & 0x0F        // Header length in 32-bit words
	ipHeaderLen := int(ihl) * 4

	if version != 4 || ipHeaderLen < minIPLen {
		return false, offset // Not IPv4 or malformed
	}
	if len(data) < offset+ipHeaderLen {
		return false, offset
	}

	p.TTL = data[offset+8]
	p.Protocol = data[offset+9]

	// Source IP is at bytes 12–15 (big-endian network byte order).
	// We store it packed as little-endian uint32 (first octet in low byte)
	// to match the C++ FiveTuple encoding.
	srcIP := data[offset+12 : offset+16]
	dstIP := data[offset+16 : offset+20]

	p.SrcIPRaw = uint32(srcIP[0]) | uint32(srcIP[1])<<8 | uint32(srcIP[2])<<16 | uint32(srcIP[3])<<24
	p.DstIPRaw = uint32(dstIP[0]) | uint32(dstIP[1])<<8 | uint32(dstIP[2])<<16 | uint32(dstIP[3])<<24

	p.SrcIP = net.IP(srcIP).String()
	p.DstIP = net.IP(dstIP).String()
	p.HasIP = true

	return true, offset + ipHeaderLen
}

// ============================================================================
// parseTCP — TCP header (variable length, minimum 20 bytes)
//
//   Bytes  0– 1: Source port (big-endian)
//   Bytes  2– 3: Destination port (big-endian)
//   Bytes  4– 7: Sequence number (big-endian)
//   Bytes  8–11: Acknowledgment number (big-endian)
//   Byte  12:    Data offset (high 4 bits) — header length / 4
//   Byte  13:    Flags bitmask (FIN SYN RST PSH ACK URG)
// ============================================================================
func parseTCP(data []byte, offset int, p *ParsedPacket) (bool, int) {
	const minTCPLen = 20
	if len(data) < offset+minTCPLen {
		return false, offset
	}

	p.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
	p.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	p.SeqNum = binary.BigEndian.Uint32(data[offset+4 : offset+8])
	p.AckNum = binary.BigEndian.Uint32(data[offset+8 : offset+12])

	dataOffset := (data[offset+12] >> 4) & 0x0F // header length in 32-bit words
	tcpHeaderLen := int(dataOffset) * 4

	if tcpHeaderLen < minTCPLen || len(data) < offset+tcpHeaderLen {
		return false, offset
	}

	p.TCPFlags = data[offset+13]
	p.HasTCP = true

	return true, offset + tcpHeaderLen
}

// ============================================================================
// parseUDP — UDP header (fixed 8 bytes)
//
//   Bytes 0–1: Source port
//   Bytes 2–3: Destination port
//   Bytes 4–5: Length (header + data)
//   Bytes 6–7: Checksum
// ============================================================================
func parseUDP(data []byte, offset int, p *ParsedPacket) (bool, int) {
	const udpLen = 8
	if len(data) < offset+udpLen {
		return false, offset
	}

	p.SrcPort = binary.BigEndian.Uint16(data[offset : offset+2])
	p.DstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
	p.HasUDP = true

	return true, offset + udpLen
}

// ============================================================================
// Helper functions
// ============================================================================

// macToString formats 6 bytes as a colon-separated hex MAC address.
func macToString(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		b[0], b[1], b[2], b[3], b[4], b[5])
}

// tcpFlagsString returns a human-readable list of set TCP flags.
func tcpFlagsString(flags uint8) string {
	var parts []string
	if flags&tcpFlagSYN != 0 {
		parts = append(parts, "SYN")
	}
	if flags&tcpFlagACK != 0 {
		parts = append(parts, "ACK")
	}
	if flags&tcpFlagFIN != 0 {
		parts = append(parts, "FIN")
	}
	if flags&tcpFlagRST != 0 {
		parts = append(parts, "RST")
	}
	if flags&tcpFlagPSH != 0 {
		parts = append(parts, "PSH")
	}
	if flags&tcpFlagURG != 0 {
		parts = append(parts, "URG")
	}
	if len(parts) == 0 {
		return "none"
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += "|" + p
	}
	return result
}
