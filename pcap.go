package main

// pcap.go — reading and writing the .pcap file format
//
// A .pcap file has a simple binary layout:
//
//   ┌──────────────────────────┐
//   │  Global header (24 B)    │  written once at the start
//   ├──────────────────────────┤
//   │  Packet header (16 B)    │  \  repeated for
//   │  Packet data   (N B)     │  /  every packet
//   ├──────────────────────────┤
//   │  …                       │
//   └──────────────────────────┘
//
// We read packets one at a time to keep memory use constant regardless
// of file size.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// ============================================================================
// PCAP magic numbers
//
// The first 4 bytes of every .pcap file identify the byte order.
// 0xa1b2c3d4 means the file was written in the same byte order as the
// reader ("native").  0xd4c3b2a1 means it was written in the opposite
// order and we need to swap all multi-byte values.
// ============================================================================
const (
	pcapMagicNative  = 0xa1b2c3d4
	pcapMagicSwapped = 0xd4c3b2a1
)

// GlobalHeader is the 24-byte header that starts every .pcap file.
// It describes the file format and the link-layer type of captured packets.
type GlobalHeader struct {
	MagicNumber  uint32 // 0xa1b2c3d4 (or swapped)
	VersionMajor uint16 // Usually 2
	VersionMinor uint16 // Usually 4
	Thiszone     int32  // GMT offset (always 0 in practice)
	Sigfigs      uint32 // Timestamp accuracy (always 0)
	Snaplen      uint32 // Maximum bytes per captured packet
	Network      uint32 // Link-layer type: 1 = Ethernet
}

// PacketHeader is the 16-byte header that precedes each captured packet.
type PacketHeader struct {
	TsSec   uint32 // Capture timestamp — seconds since Unix epoch
	TsUsec  uint32 // Capture timestamp — microseconds fraction
	InclLen uint32 // Bytes actually stored in the file for this packet
	OrigLen uint32 // Original on-wire packet length (may be larger than InclLen)
}

// RawPacket bundles the 16-byte packet header with the captured bytes.
type RawPacket struct {
	Header PacketHeader
	Data   []byte // The raw captured bytes (up to InclLen long)
}

// ============================================================================
// PcapReader — sequential reader for .pcap files
// ============================================================================

// PcapReader reads packets from a .pcap file one at a time.
// Call Open() first, then ReadNext() in a loop.
type PcapReader struct {
	file        *os.File
	byteOrder   binary.ByteOrder // little-endian (native) or big-endian (swapped)
	GlobalHdr   GlobalHeader
}

// Open opens a .pcap file and reads its global header.
// Returns an error if the file cannot be opened or has an invalid magic number.
func (r *PcapReader) Open(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("cannot open pcap file: %w", err)
	}
	r.file = f

	// Read the 4-byte magic number first to determine byte order.
	var magic uint32
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return fmt.Errorf("cannot read magic number: %w", err)
	}

	switch magic {
	case pcapMagicNative:
		// File was written on a little-endian machine; no swapping needed.
		r.byteOrder = binary.LittleEndian
	case pcapMagicSwapped:
		// File was written on a big-endian machine; we must swap.
		r.byteOrder = binary.BigEndian
	default:
		return fmt.Errorf("invalid pcap magic 0x%08x — not a pcap file", magic)
	}

	// Re-read the whole 24-byte global header now that we know byte order.
	// Seek back to the beginning of the file first.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek failed: %w", err)
	}
	if err := binary.Read(f, r.byteOrder, &r.GlobalHdr); err != nil {
		return fmt.Errorf("cannot read global header: %w", err)
	}

	fmt.Printf("Opened PCAP: version %d.%d  snaplen=%d  link=%d\n",
		r.GlobalHdr.VersionMajor, r.GlobalHdr.VersionMinor,
		r.GlobalHdr.Snaplen, r.GlobalHdr.Network)

	return nil
}

// ReadNext reads the next packet from the file.
// Returns (packet, nil) on success.
// Returns (nil, io.EOF) at end of file (not an error — just stop looping).
// Returns (nil, err) on any real error.
func (r *PcapReader) ReadNext() (*RawPacket, error) {
	pkt := &RawPacket{}

	// Read the 16-byte per-packet header.
	if err := binary.Read(r.file, r.byteOrder, &pkt.Header); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, io.EOF // Normal end of capture file
		}
		return nil, fmt.Errorf("reading packet header: %w", err)
	}

	// Sanity check: captured length should never exceed snaplen or 64 KB.
	if pkt.Header.InclLen > r.GlobalHdr.Snaplen || pkt.Header.InclLen > 65535 {
		return nil, fmt.Errorf("bogus packet length %d", pkt.Header.InclLen)
	}

	// Read exactly InclLen bytes of packet data.
	pkt.Data = make([]byte, pkt.Header.InclLen)
	if _, err := io.ReadFull(r.file, pkt.Data); err != nil {
		return nil, fmt.Errorf("reading packet data: %w", err)
	}

	return pkt, nil
}

// Close releases the underlying file handle.
func (r *PcapReader) Close() {
	if r.file != nil {
		r.file.Close()
	}
}

// ============================================================================
// PcapWriter — append-only writer for .pcap files
// ============================================================================

// PcapWriter creates a new .pcap file and writes packets to it.
// The global header is written once on Create(); then WritePacket() is called
// for every packet that passes the blocking rules.
type PcapWriter struct {
	file      *os.File
	byteOrder binary.ByteOrder
}

// Create opens (or truncates) the output file and writes the global header.
// The header is copied from the reader so link-type and snaplen match.
func (w *PcapWriter) Create(path string, hdr GlobalHeader) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("cannot create output file: %w", err)
	}
	w.file = f
	w.byteOrder = binary.LittleEndian // Always write in native little-endian

	// Normalise the magic number so the output is always native-endian.
	hdr.MagicNumber = pcapMagicNative

	if err := binary.Write(f, w.byteOrder, hdr); err != nil {
		return fmt.Errorf("writing global header: %w", err)
	}
	return nil
}

// WritePacket writes one allowed packet (header + data) to the output file.
// The caller must NOT call this for blocked packets.
func (w *PcapWriter) WritePacket(pkt *RawPacket) error {
	// Write the 16-byte packet header.
	if err := binary.Write(w.file, w.byteOrder, pkt.Header); err != nil {
		return fmt.Errorf("writing packet header: %w", err)
	}
	// Write the raw packet bytes.
	if _, err := w.file.Write(pkt.Data); err != nil {
		return fmt.Errorf("writing packet data: %w", err)
	}
	return nil
}

// Close flushes and closes the output file.
func (w *PcapWriter) Close() {
	if w.file != nil {
		w.file.Close()
	}
}
