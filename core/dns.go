package core

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// DNSResult holds the result of a DNS lookup.
type DNSResult struct {
	FQDN string
	IPs  []string
}

// WildcardDetector detects and filters wildcard DNS responses.
type WildcardDetector struct {
	ips map[string]struct{}
}

// NewWildcardDetector creates a new wildcard detector by probing a random subdomain.
func NewWildcardDetector(ctx context.Context, domain string, timeout time.Duration) (*WildcardDetector, error) {
	randomSub := generateRandomSubdomain(12)
	fqdn := randomSub + "." + domain

	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
	}

	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.LookupHost(dnsCtx, fqdn)
	if err != nil || len(ips) == 0 {
		return &WildcardDetector{ips: nil}, nil
	}

	wildcardIPs := make(map[string]struct{})
	for _, ip := range ips {
		wildcardIPs[ip] = struct{}{}
	}

	return &WildcardDetector{ips: wildcardIPs}, nil
}

// HasWildcard returns true if wildcards were detected.
func (wd *WildcardDetector) HasWildcard() bool {
	return len(wd.ips) > 0
}

// WildcardIPs returns the detected wildcard IP addresses.
func (wd *WildcardDetector) WildcardIPs() []string {
	if len(wd.ips) == 0 {
		return nil
	}
	keys := make([]string, 0, len(wd.ips))
	for k := range wd.ips {
		keys = append(keys, k)
	}
	return keys
}

// IsWildcardResponse returns true if all IPs match the wildcard pattern.
func (wd *WildcardDetector) IsWildcardResponse(ips []string) bool {
	if len(wd.ips) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if _, ok := wd.ips[ip]; !ok {
			return false
		}
	}
	return true
}

// Lookup performs a DNS lookup and writes results to the state store.
// It is UI-agnostic - it knows nothing about the TUI.
func Lookup(ctx context.Context, resolver *net.Resolver, sub string, domain string, wd *WildcardDetector, negCache *NegCache, timeout time.Duration, onResult func(fqdn string, ips []string)) error {
	fqdn := sub + "." + domain

	// Check negative cache first
	if negCache != nil && negCache.IsCached(fqdn) {
		return nil
	}

	dnsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolver.LookupHost(dnsCtx, fqdn)
	if err != nil {
		// Cache negative response on timeout (likely NXDOMAIN)
		if negCache != nil && errors.Is(err, context.DeadlineExceeded) {
			negCache.Add(fqdn)
		}
		return nil
	}

	if len(ips) == 0 {
		return nil
	}

	// Filter wildcard responses
	if wd != nil && wd.IsWildcardResponse(ips) {
		return nil
	}

	// Report result (callback to avoid TUI dependency)
	onResult(fqdn, ips)
	return nil
}

// generateRandomSubdomain generates a random subdomain string.
func generateRandomSubdomain(length int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz0123456789-"
	result := make([]byte, length)
	for i := range result {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		result[i] = alphabet[n.Int64()]
	}
	return string(result)
}

// PrintResult outputs a result to stdout (for non-TUI mode).
func PrintResult(fqdn string, ips []string) {
	fmt.Printf("%s -> %s\n", fqdn, strings.Join(ips, ", "))
}
