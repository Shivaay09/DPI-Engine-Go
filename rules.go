package main

// rules.go — blocking rule manager
//
// The RuleManager holds three independent rule sets that can be checked
// together for any incoming packet:
//
//   1. IP rules    — block all traffic from a source IP address
//   2. App rules   — block a whole application (e.g., all YouTube)
//   3. Domain rules — block by hostname substring (e.g., "tiktok")
//   4. Port rules  — block a destination port
//
// Rules are checked in the order above; the first match short-circuits.
//
// In the C++ original these were protected by shared_mutex (multiple readers,
// one writer).  In Go we use sync.RWMutex for the same semantics, but since
// the engine is single-threaded in this version we could skip locking
// entirely.  We keep it for correctness and future concurrency.

import (
	"fmt"
	"strings"
	"sync"
)

// BlockReason describes which rule caused a packet to be blocked.
type BlockReason struct {
	Kind  string // "ip", "app", "domain", "port"
	Value string // The matched value (e.g., "192.168.1.50", "YouTube")
}

func (b BlockReason) String() string {
	return fmt.Sprintf("[%s: %s]", b.Kind, b.Value)
}

// ============================================================================
// RuleManager
// ============================================================================

// RuleManager stores all blocking rules and provides thread-safe lookup.
// All public methods may be called concurrently.
type RuleManager struct {
	// IP rules — map of packed uint32 IP → true
	ipMu       sync.RWMutex
	blockedIPs map[uint32]struct{}

	// App rules — set of AppType values
	appMu       sync.RWMutex
	blockedApps map[AppType]struct{}

	// Domain rules
	//   exactDomains  — full hostname match ("www.youtube.com")
	//   domainPatterns — wildcard prefix match ("*.youtube.com")
	//   substrings     — simple contains match ("tiktok")
	domainMu      sync.RWMutex
	exactDomains  map[string]struct{}
	domainPatterns []string // patterns starting with "*."
	substrings    []string  // plain substring patterns (from --block-domain)

	// Port rules
	portMu      sync.RWMutex
	blockedPorts map[uint16]struct{}
}

// NewRuleManager creates an empty RuleManager.
func NewRuleManager() *RuleManager {
	return &RuleManager{
		blockedIPs:   make(map[uint32]struct{}),
		blockedApps:  make(map[AppType]struct{}),
		exactDomains: make(map[string]struct{}),
		blockedPorts: make(map[uint16]struct{}),
	}
}

// ── IP rules ─────────────────────────────────────────────────────────────────

// BlockIPString parses a dotted-decimal IP and adds it to the IP blocklist.
func (r *RuleManager) BlockIPString(ip string) {
	packed := parseIPString(ip)
	r.ipMu.Lock()
	r.blockedIPs[packed] = struct{}{}
	r.ipMu.Unlock()
	fmt.Printf("[Rules] Blocked IP: %s\n", ip)
}

// IsIPBlocked returns true if the given packed uint32 IP is on the blocklist.
func (r *RuleManager) IsIPBlocked(ip uint32) bool {
	r.ipMu.RLock()
	_, ok := r.blockedIPs[ip]
	r.ipMu.RUnlock()
	return ok
}

// ── App rules ────────────────────────────────────────────────────────────────

// BlockApp adds an AppType to the app blocklist.
func (r *RuleManager) BlockApp(app AppType) {
	r.appMu.Lock()
	r.blockedApps[app] = struct{}{}
	r.appMu.Unlock()
	fmt.Printf("[Rules] Blocked app: %s\n", app)
}

// BlockAppString looks up an AppType by name and adds it to the blocklist.
// Prints a warning and returns false if the name is not recognised.
func (r *RuleManager) BlockAppString(name string) bool {
	app, ok := AppTypeFromString(name)
	if !ok {
		fmt.Printf("[Rules] WARNING: unknown app %q\n", name)
		return false
	}
	r.BlockApp(app)
	return true
}

// IsAppBlocked returns true if the given AppType is on the blocklist.
func (r *RuleManager) IsAppBlocked(app AppType) bool {
	r.appMu.RLock()
	_, ok := r.blockedApps[app]
	r.appMu.RUnlock()
	return ok
}

// ── Domain rules ─────────────────────────────────────────────────────────────

// BlockDomain adds a domain rule.  Three forms are accepted:
//
//   "*.example.com"   — wildcard: blocks any subdomain of example.com
//   "www.example.com" — exact hostname match
//   "tiktok"          — substring match (matches tiktok.com, www.tiktok.com, …)
func (r *RuleManager) BlockDomain(domain string) {
	lower := strings.ToLower(domain)
	r.domainMu.Lock()
	if strings.HasPrefix(lower, "*.") {
		r.domainPatterns = append(r.domainPatterns, lower)
	} else if strings.ContainsRune(lower, '.') {
		// Has a dot → treat as exact match
		r.exactDomains[lower] = struct{}{}
	} else {
		// No dot → substring match (e.g., "tiktok" matches "www.tiktok.com")
		r.substrings = append(r.substrings, lower)
	}
	r.domainMu.Unlock()
	fmt.Printf("[Rules] Blocked domain: %s\n", domain)
}

// IsDomainBlocked returns true if the hostname matches any domain rule.
func (r *RuleManager) IsDomainBlocked(domain string) bool {
	if domain == "" {
		return false
	}
	lower := strings.ToLower(domain)

	r.domainMu.RLock()
	defer r.domainMu.RUnlock()

	// 1. Exact match
	if _, ok := r.exactDomains[lower]; ok {
		return true
	}

	// 2. Wildcard prefix match  (*.example.com matches sub.example.com)
	for _, pat := range r.domainPatterns {
		suffix := pat[1:] // strip leading "*" to get ".example.com"
		if strings.HasSuffix(lower, suffix) {
			return true
		}
		// Also match the apex domain (example.com should match *.example.com)
		if lower == pat[2:] { // strip "*."
			return true
		}
	}

	// 3. Substring match ("tiktok" matches "www.tiktok.com")
	for _, sub := range r.substrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}

	return false
}

// ── Port rules ───────────────────────────────────────────────────────────────

// BlockPort adds a destination port to the port blocklist.
func (r *RuleManager) BlockPort(port uint16) {
	r.portMu.Lock()
	r.blockedPorts[port] = struct{}{}
	r.portMu.Unlock()
	fmt.Printf("[Rules] Blocked port: %d\n", port)
}

// IsPortBlocked returns true if the destination port is blocked.
func (r *RuleManager) IsPortBlocked(port uint16) bool {
	r.portMu.RLock()
	_, ok := r.blockedPorts[port]
	r.portMu.RUnlock()
	return ok
}

// ── Combined check ────────────────────────────────────────────────────────────

// ShouldBlock checks all rule sets and returns the first matching BlockReason.
// Returns nil if the packet should be forwarded.
//
// Check order: IP → port → app → domain
// (Most specific / cheapest checks first.)
func (r *RuleManager) ShouldBlock(srcIP uint32, dstPort uint16, app AppType, domain string) *BlockReason {
	if r.IsIPBlocked(srcIP) {
		return &BlockReason{Kind: "ip", Value: uint32ToIP(srcIP)}
	}
	if r.IsPortBlocked(dstPort) {
		return &BlockReason{Kind: "port", Value: fmt.Sprintf("%d", dstPort)}
	}
	if r.IsAppBlocked(app) {
		return &BlockReason{Kind: "app", Value: app.String()}
	}
	if r.IsDomainBlocked(domain) {
		return &BlockReason{Kind: "domain", Value: domain}
	}
	return nil
}
