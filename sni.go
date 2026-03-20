package main

// sni.go — Deep Packet Inspection: extracting hostnames from application-layer data
//
// Even though HTTPS traffic is encrypted, the very first message of a TLS
// handshake (the "Client Hello") is sent in PLAINTEXT and contains the
// target hostname in an extension called "Server Name Indication" (SNI).
//
// This file implements three extractors:
//   1. ExtractTLSSNI   — reads the SNI from a TLS Client Hello
//   2. ExtractHTTPHost — reads the Host: header from plain HTTP requests
//   3. ExtractDNSQuery — reads the queried domain from a DNS packet
//
// The TLS packet layout we parse:
//
//   ┌──────────────────────────────────────────────────────────┐
//   │ TLS Record Header (5 bytes)                              │
//   │   Byte 0:    Content Type = 0x16 (Handshake)            │
//   │   Bytes 1-2: Legacy version (0x0301 = TLS 1.0)          │
//   │   Bytes 3-4: Record length                               │
//   ├──────────────────────────────────────────────────────────┤
//   │ Handshake Header (4 bytes)                               │
//   │   Byte 0:    Handshake Type = 0x01 (Client Hello)        │
//   │   Bytes 1-3: Handshake body length (3-byte big-endian)   │
//   ├──────────────────────────────────────────────────────────┤
//   │ Client Hello Body                                        │
//   │   Bytes 0-1:   Client version                            │
//   │   Bytes 2-33:  Random (32 bytes)                         │
//   │   Byte  34:    Session ID length (N)                     │
//   │   N bytes:     Session ID                                │
//   │   2 bytes:     Cipher suites length (M)                  │
//   │   M bytes:     Cipher suites                             │
//   │   1 byte:      Compression methods length (K)            │
//   │   K bytes:     Compression methods                       │
//   │   2 bytes:     Extensions length                         │
//   │   ... Extensions ...                                     │
//   │     ┌─────────────────────────────────────────────┐     │
//   │     │  SNI Extension (type 0x0000)                │     │
//   │     │    2 bytes: SNI list length                 │     │
//   │     │    1 byte:  SNI type = 0x00 (hostname)      │     │
//   │     │    2 bytes: hostname length (L)              │     │
//   │     │    L bytes: hostname  ← THIS IS WHAT WE WANT│     │
//   │     └─────────────────────────────────────────────┘     │
//   └──────────────────────────────────────────────────────────┘

import (
	"encoding/binary"
	"strings"
)

// ── TLS constants ────────────────────────────────────────────────────────────

const (
	tlsContentHandshake = 0x16 // TLS record content type: Handshake
	tlsHandshakeHello   = 0x01 // Handshake message type: ClientHello
	tlsExtensionSNI     = 0x0000
	tlsSNITypeHostname  = 0x00
)

// ============================================================================
// ExtractTLSSNI — parse a TLS Client Hello and return the SNI hostname
//
// Returns ("", false) if:
//   - the payload is too short
//   - the first byte is not 0x16 (not a TLS Handshake record)
//   - the handshake type is not 0x01 (not a Client Hello)
//   - the SNI extension is absent (e.g., IP address connections)
// ============================================================================
func ExtractTLSSNI(payload []byte) (string, bool) {
	// ── Step 1: Validate TLS record header ──────────────────────────────────
	//
	// We need at least 9 bytes:
	//   5 (TLS record header) + 4 (Handshake header minimum)
	if len(payload) < 9 {
		return "", false
	}

	// Byte 0 must be 0x16 = Handshake
	if payload[0] != tlsContentHandshake {
		return "", false
	}

	// Bytes 1-2: legacy TLS version — must be in range 0x0300–0x0304
	version := binary.BigEndian.Uint16(payload[1:3])
	if version < 0x0300 || version > 0x0304 {
		return "", false
	}

	// Bytes 3-4: record length — must fit within payload
	recordLen := binary.BigEndian.Uint16(payload[3:5])
	if int(recordLen) > len(payload)-5 {
		return "", false
	}

	// ── Step 2: Validate Handshake header ───────────────────────────────────
	//
	// The Handshake layer starts at byte 5.
	// Byte 5: Handshake type must be 0x01 (Client Hello)
	if payload[5] != tlsHandshakeHello {
		return "", false
	}

	// Bytes 6-8: 3-byte big-endian body length
	// (Note: not used for bounds checking here — we use len(payload) directly)

	// ── Step 3: Walk past the fixed-size Client Hello fields ────────────────
	//
	// We use a "cursor" offset and helper functions that return false
	// if advancing would exceed the slice length.
	offset := 9 // Start of Client Hello body (after TLS record + handshake headers)

	// Skip client version (2 bytes)
	offset += 2

	// Skip random (32 bytes)
	offset += 32

	// Skip session ID (1-byte length prefix + data)
	if offset >= len(payload) {
		return "", false
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Skip cipher suites (2-byte length prefix + data)
	if offset+2 > len(payload) {
		return "", false
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2 + cipherSuitesLen

	// Skip compression methods (1-byte length prefix + data)
	if offset >= len(payload) {
		return "", false
	}
	compressionLen := int(payload[offset])
	offset += 1 + compressionLen

	// ── Step 4: Read extensions length ──────────────────────────────────────
	if offset+2 > len(payload) {
		return "", false // No extensions at all
	}
	extTotalLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	extEnd := offset + extTotalLen
	if extEnd > len(payload) {
		extEnd = len(payload) // Truncated packet — parse as far as we can
	}

	// ── Step 5: Iterate extensions looking for type 0x0000 (SNI) ────────────
	//
	// Each extension has a 4-byte header:
	//   2 bytes: extension type
	//   2 bytes: extension data length
	// followed by the extension data.
	for offset+4 <= extEnd {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extDataLen > extEnd {
			break // Malformed extension
		}

		if extType != tlsExtensionSNI {
			// Not the SNI extension — skip it
			offset += extDataLen
			continue
		}

		// ── Step 6: Parse SNI extension data ────────────────────────────────
		//
		// SNI extension body:
		//   2 bytes: SNI list length
		//   1 byte:  SNI name type (0x00 = hostname)
		//   2 bytes: hostname length
		//   N bytes: hostname
		if extDataLen < 5 {
			return "", false
		}

		// We don't need the list length — just step over it
		// Byte 2 is SNI type; must be 0x00 (hostname)
		if payload[offset+2] != tlsSNITypeHostname {
			return "", false
		}

		hostnameLen := int(binary.BigEndian.Uint16(payload[offset+3 : offset+5]))
		if offset+5+hostnameLen > extEnd {
			return "", false
		}

		hostname := string(payload[offset+5 : offset+5+hostnameLen])
		return hostname, true
	}

	return "", false // SNI extension not found
}

// ============================================================================
// ExtractHTTPHost — parse an HTTP/1.x request and return the Host: value
//
// Plain HTTP (port 80) sends requests like:
//
//   GET /path HTTP/1.1\r\n
//   Host: www.example.com\r\n
//   ...
//
// We search for "Host:" (case-insensitive) and return the value.
// Port numbers in the Host header (e.g., "example.com:8080") are stripped.
// ============================================================================
func ExtractHTTPHost(payload []byte) (string, bool) {
	if len(payload) < 4 {
		return "", false
	}

	// Quickly verify it looks like an HTTP request by checking the first verb.
	start := string(payload)
	if !strings.HasPrefix(start, "GET ") &&
		!strings.HasPrefix(start, "POST ") &&
		!strings.HasPrefix(start, "PUT ") &&
		!strings.HasPrefix(start, "HEAD ") &&
		!strings.HasPrefix(start, "DELETE ") &&
		!strings.HasPrefix(start, "PATCH ") &&
		!strings.HasPrefix(start, "OPTIONS ") {
		return "", false
	}

	// Case-insensitive search for the Host header.
	lower := strings.ToLower(start)
	hostIdx := strings.Index(lower, "\nhost:")
	if hostIdx == -1 {
		hostIdx = strings.Index(lower, "\r\nhost:")
	}
	if hostIdx == -1 {
		return "", false
	}

	// Advance past "\nhost:" or "\r\nhost:"
	valueStart := hostIdx + strings.Index(lower[hostIdx:], ":")+1
	// Skip optional whitespace after the colon
	for valueStart < len(start) && (start[valueStart] == ' ' || start[valueStart] == '\t') {
		valueStart++
	}

	// Read until end of line
	valueEnd := valueStart
	for valueEnd < len(start) && start[valueEnd] != '\r' && start[valueEnd] != '\n' {
		valueEnd++
	}

	if valueEnd <= valueStart {
		return "", false
	}

	host := strings.TrimSpace(start[valueStart:valueEnd])
	// Strip optional port (e.g., "example.com:8080" → "example.com")
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}

	return host, true
}

// ============================================================================
// ExtractDNSQuery — return the first question name from a DNS query packet
//
// DNS packet layout (after UDP header):
//
//   Bytes 0-1:   Transaction ID
//   Bytes 2-3:   Flags (bit 15 = QR: 0=query, 1=response)
//   Bytes 4-5:   Question count (QDCOUNT)
//   Bytes 6-7:   Answer count
//   Bytes 8-9:   Authority count
//   Bytes 10-11: Additional count
//   Bytes 12+:   Questions
//
// Each question name is a sequence of length-prefixed labels ending in 0x00:
//   3 www  → 0x03 0x77 0x77 0x77
//   7 example → 0x07 0x65 0x78 ...
//   3 com  → 0x03 0x63 0x6f 0x6d
//   end    → 0x00
// ============================================================================
func ExtractDNSQuery(payload []byte) (string, bool) {
	if len(payload) < 12 {
		return "", false // Minimum DNS header is 12 bytes
	}

	// Bit 15 of the Flags field (byte 2, MSB) is 0 for queries, 1 for responses.
	if payload[2]&0x80 != 0 {
		return "", false // This is a DNS response, not a query
	}

	// QDCOUNT (bytes 4-5) must be > 0
	qdcount := binary.BigEndian.Uint16(payload[4:6])
	if qdcount == 0 {
		return "", false
	}

	// Parse the first question name starting at byte 12.
	offset := 12
	var labels []string

	for offset < len(payload) {
		labelLen := int(payload[offset])
		offset++

		if labelLen == 0 {
			break // End of domain name
		}

		// Labels longer than 63 bytes indicate DNS compression pointers.
		// We don't follow compression in this simplified version.
		if labelLen > 63 {
			break
		}

		if offset+labelLen > len(payload) {
			break
		}
		labels = append(labels, string(payload[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(labels) == 0 {
		return "", false
	}

	domain := strings.Join(labels, ".")
	return domain, true
}
