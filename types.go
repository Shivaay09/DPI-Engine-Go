// Package dpi_engine implements a Deep Packet Inspection engine that reads
// .pcap files, classifies network traffic by application (YouTube, Facebook,
// etc.) using TLS SNI extraction, applies blocking rules, and writes filtered
// output to a new .pcap file.
package main

import (
	"fmt"
	"strings"
)

// ============================================================================
// FiveTuple — the unique key for a network connection/flow
//
// Every TCP/UDP connection is identified by exactly these five fields.
// Packets sharing the same five-tuple belong to the same conversation.
// We use this as a map key to track flows across multiple packets.
// ============================================================================
type FiveTuple struct {
	SrcIP    uint32 // Source IP address (4 bytes, network byte order)
	DstIP    uint32 // Destination IP address
	SrcPort  uint16 // Source TCP/UDP port
	DstPort  uint16 // Destination TCP/UDP port
	Protocol uint8  // IP protocol number: 6 = TCP, 17 = UDP
}

// String returns a human-readable representation of the five-tuple,
// e.g. "192.168.1.1:54321 -> 142.250.185.46:443 (TCP)"
func (t FiveTuple) String() string {
	proto := "?"
	switch t.Protocol {
	case 6:
		proto = "TCP"
	case 17:
		proto = "UDP"
	}
	return fmt.Sprintf("%s:%d -> %s:%d (%s)",
		uint32ToIP(t.SrcIP), t.SrcPort,
		uint32ToIP(t.DstIP), t.DstPort,
		proto)
}

// ============================================================================
// AppType — application-level classification for a flow
//
// After inspecting the TLS SNI (or HTTP Host header), we map each flow to
// one of these known application types.  This drives the blocking logic.
// ============================================================================
type AppType int

const (
	AppUnknown    AppType = iota // Not yet classified
	AppHTTP                      // Plain HTTP (port 80), no host identified
	AppHTTPS                     // HTTPS (port 443), no SNI extracted yet
	AppDNS                       // DNS query (port 53)
	AppTLS                       // TLS but SNI not recognised
	AppQUIC                      // QUIC (UDP 443)
	AppGoogle                    // google.com, gstatic.com, googleapis.com ...
	AppFacebook                  // facebook.com, fbcdn.net, meta.com ...
	AppYouTube                   // youtube.com, ytimg.com ...
	AppTwitter                   // twitter.com, x.com, twimg.com ...
	AppInstagram                 // instagram.com, cdninstagram.com ...
	AppNetflix                   // netflix.com, nflxvideo.net ...
	AppAmazon                    // amazon.com, amazonaws.com, cloudfront.net ...
	AppMicrosoft                 // microsoft.com, office.com, azure.com ...
	AppApple                     // apple.com, icloud.com, mzstatic.com ...
	AppWhatsApp                  // whatsapp.com, wa.me ...
	AppTelegram                  // telegram.org, t.me ...
	AppTikTok                    // tiktok.com, tiktokcdn.com, bytedance.com ...
	AppSpotify                   // spotify.com, scdn.co ...
	AppZoom                      // zoom.us ...
	AppDiscord                   // discord.com, discordapp.com ...
	AppGitHub                    // github.com, githubusercontent.com ...
	AppCloudflare                // cloudflare.com ...
)

// appTypeNames maps each AppType constant to its display string.
// Used for reports and CLI argument matching.
var appTypeNames = map[AppType]string{
	AppUnknown:    "Unknown",
	AppHTTP:       "HTTP",
	AppHTTPS:      "HTTPS",
	AppDNS:        "DNS",
	AppTLS:        "TLS",
	AppQUIC:       "QUIC",
	AppGoogle:     "Google",
	AppFacebook:   "Facebook",
	AppYouTube:    "YouTube",
	AppTwitter:    "Twitter/X",
	AppInstagram:  "Instagram",
	AppNetflix:    "Netflix",
	AppAmazon:     "Amazon",
	AppMicrosoft:  "Microsoft",
	AppApple:      "Apple",
	AppWhatsApp:   "WhatsApp",
	AppTelegram:   "Telegram",
	AppTikTok:     "TikTok",
	AppSpotify:    "Spotify",
	AppZoom:       "Zoom",
	AppDiscord:    "Discord",
	AppGitHub:     "GitHub",
	AppCloudflare: "Cloudflare",
}

// String returns the display name for an AppType.
func (a AppType) String() string {
	if name, ok := appTypeNames[a]; ok {
		return name
	}
	return "Unknown"
}

// AppTypeFromString looks up an AppType by its display name (case-insensitive).
// Returns AppUnknown and false if not found.
func AppTypeFromString(s string) (AppType, bool) {
	lower := strings.ToLower(s)
	for t, name := range appTypeNames {
		if strings.ToLower(name) == lower {
			return t, true
		}
	}
	return AppUnknown, false
}

// ============================================================================
// SNIToAppType — classify a domain/SNI string into an AppType
//
// The TLS Client Hello sends the target hostname in plaintext (SNI field)
// before encryption begins.  We substring-match the SNI against known
// patterns to identify the application.
// ============================================================================
func SNIToAppType(sni string) AppType {
	if sni == "" {
		return AppUnknown
	}
	lower := strings.ToLower(sni)

	switch {
	// YouTube must come before Google — youtube.com also contains "google" CDN refs
	case strings.Contains(lower, "youtube") ||
		strings.Contains(lower, "ytimg") ||
		strings.Contains(lower, "youtu.be") ||
		strings.Contains(lower, "yt3.ggpht"):
		return AppYouTube

	// Google
	case strings.Contains(lower, "google") ||
		strings.Contains(lower, "gstatic") ||
		strings.Contains(lower, "googleapis") ||
		strings.Contains(lower, "gvt1"):
		return AppGoogle

	// Facebook / Meta
	case strings.Contains(lower, "facebook") ||
		strings.Contains(lower, "fbcdn") ||
		strings.Contains(lower, "fb.com") ||
		strings.Contains(lower, "fbsbx") ||
		strings.Contains(lower, "meta.com"):
		return AppFacebook

	// Instagram (owned by Meta)
	case strings.Contains(lower, "instagram") ||
		strings.Contains(lower, "cdninstagram"):
		return AppInstagram

	// WhatsApp (owned by Meta)
	case strings.Contains(lower, "whatsapp") ||
		strings.Contains(lower, "wa.me"):
		return AppWhatsApp

	// Twitter / X
	case strings.Contains(lower, "twitter") ||
		strings.Contains(lower, "twimg") ||
		strings.Contains(lower, "x.com") ||
		strings.Contains(lower, "t.co"):
		return AppTwitter

	// Netflix
	case strings.Contains(lower, "netflix") ||
		strings.Contains(lower, "nflxvideo") ||
		strings.Contains(lower, "nflximg"):
		return AppNetflix

	// Amazon / AWS
	case strings.Contains(lower, "amazon") ||
		strings.Contains(lower, "amazonaws") ||
		strings.Contains(lower, "cloudfront") ||
		strings.Contains(lower, "aws"):
		return AppAmazon

	// Microsoft
	case strings.Contains(lower, "microsoft") ||
		strings.Contains(lower, "msn.com") ||
		strings.Contains(lower, "office") ||
		strings.Contains(lower, "azure") ||
		strings.Contains(lower, "live.com") ||
		strings.Contains(lower, "outlook") ||
		strings.Contains(lower, "bing"):
		return AppMicrosoft

	// Apple
	case strings.Contains(lower, "apple") ||
		strings.Contains(lower, "icloud") ||
		strings.Contains(lower, "mzstatic") ||
		strings.Contains(lower, "itunes"):
		return AppApple

	// Telegram
	case strings.Contains(lower, "telegram") ||
		strings.Contains(lower, "t.me"):
		return AppTelegram

	// TikTok / ByteDance
	case strings.Contains(lower, "tiktok") ||
		strings.Contains(lower, "tiktokcdn") ||
		strings.Contains(lower, "musical.ly") ||
		strings.Contains(lower, "bytedance"):
		return AppTikTok

	// Spotify
	case strings.Contains(lower, "spotify") ||
		strings.Contains(lower, "scdn.co"):
		return AppSpotify

	// Zoom
	case strings.Contains(lower, "zoom"):
		return AppZoom

	// Discord
	case strings.Contains(lower, "discord") ||
		strings.Contains(lower, "discordapp"):
		return AppDiscord

	// GitHub
	case strings.Contains(lower, "github") ||
		strings.Contains(lower, "githubusercontent"):
		return AppGitHub

	// Cloudflare
	case strings.Contains(lower, "cloudflare"):
		return AppCloudflare
	}

	// SNI present but not in our known list — still mark as TLS/HTTPS
	return AppHTTPS
}

// ============================================================================
// Flow — per-connection state tracked across multiple packets
//
// Once we have processed the first few packets of a connection we know
// the application type and whether it should be blocked.  All subsequent
// packets of the same five-tuple inherit that decision.
// ============================================================================
type Flow struct {
	Tuple   FiveTuple
	AppType AppType // Classified application (updated when SNI is seen)
	SNI     string  // Extracted hostname ("www.youtube.com"), empty until seen
	Packets uint64  // Total packets in this flow
	Bytes   uint64  // Total bytes in this flow
	Blocked bool    // True once a blocking rule matches
}

// ============================================================================
// Helper: uint32ToIP converts a 32-bit packed IP (network order) to string.
//
// The IP is stored with the first octet in the lowest byte, so we extract
// each byte from lowest to highest.
// ============================================================================
func uint32ToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip&0xFF, (ip>>8)&0xFF, (ip>>16)&0xFF, (ip>>24)&0xFF)
}

// parseIPString converts a dotted-decimal IP string to a packed uint32.
// The first octet ends up in the lowest byte, matching how the C++ code stores it.
func parseIPString(ip string) uint32 {
	var a, b, c, d uint32
	fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	return a | (b << 8) | (c << 16) | (d << 24)
}
