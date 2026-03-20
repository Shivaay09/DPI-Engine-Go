package main

// main.go — CLI entry point for the DPI engine
//
// Usage:
//   dpi_engine <input.pcap> <output.pcap> [options]
//
// Options:
//   --block-ip     <ip>      Block all traffic from a source IP address
//   --block-app    <app>     Block an application by name (YouTube, TikTok, …)
//   --block-domain <domain>  Block a domain (exact, wildcard, or substring)
//   --block-port   <port>    Block a destination port number
//
// Example:
//   dpi_engine capture.pcap filtered.pcap \
//       --block-app YouTube \
//       --block-ip 192.168.1.50 \
//       --block-domain tiktok
//
// This file only handles argument parsing and wires things together.
// The real work happens in engine.go, parser.go, sni.go, and rules.go.

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 3 {
		printUsage(os.Args[0])
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	// Build the rule manager from CLI flags.
	rules := NewRuleManager()

	// Parse optional flags after the two positional arguments.
	args := os.Args[3:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--block-ip":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --block-ip requires an argument")
				os.Exit(1)
			}
			i++
			rules.BlockIPString(args[i])

		case "--block-app":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --block-app requires an argument")
				os.Exit(1)
			}
			i++
			if !rules.BlockAppString(args[i]) {
				// BlockAppString already printed a warning; continue.
			}

		case "--block-domain":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --block-domain requires an argument")
				os.Exit(1)
			}
			i++
			rules.BlockDomain(args[i])

		case "--block-port":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "error: --block-port requires an argument")
				os.Exit(1)
			}
			i++
			port, err := strconv.ParseUint(args[i], 10, 16)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid port %q\n", args[i])
				os.Exit(1)
			}
			rules.BlockPort(uint16(port))

		default:
			fmt.Fprintf(os.Stderr, "warning: unknown flag %q (ignored)\n", args[i])
		}
	}

	fmt.Println()

	// Create the engine and run it.
	engine := NewEngine(inputFile, outputFile, rules)
	if err := engine.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage(prog string) {
	fmt.Printf(`
DPI Engine — Deep Packet Inspection (Go port)
=============================================

Usage:
  %s <input.pcap> <output.pcap> [options]

Options:
  --block-ip     <ip>       Block all traffic from this source IP
  --block-app    <app>      Block application: YouTube, Facebook, TikTok, etc.
  --block-domain <domain>   Block domain (exact, *.wildcard, or substring)
  --block-port   <port>     Block a destination port number

Known app names:
  Unknown  HTTP  HTTPS  DNS  TLS  QUIC
  Google   Facebook  YouTube  Twitter/X  Instagram  Netflix
  Amazon   Microsoft  Apple  WhatsApp  Telegram  TikTok
  Spotify  Zoom  Discord  GitHub  Cloudflare

Examples:
  %s capture.pcap filtered.pcap --block-app YouTube
  %s capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain tiktok
  %s capture.pcap filtered.pcap --block-app TikTok --block-domain *.facebook.com
`, prog, prog, prog, prog)
}
