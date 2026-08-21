package validate

import "net/netip"

// reserved is the IPv4 special-purpose registry, RFC 6890 plus the shared
// address space of RFC 6598. Listed as prefixes rather than as netip's
// IsPrivate/IsLoopback helpers because the helpers do not cover the three
// documentation ranges, and those are what a scanner meets most: an address in
// a README is nearly always 192.0.2.1 or 203.0.113.1.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network, and 0.0.0.0 itself
	netip.MustParsePrefix("10.0.0.0/8"),      // RFC1918
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT, RFC6598
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // RFC1918
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1, documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast
	netip.MustParsePrefix("192.168.0.0/16"),  // RFC1918
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking, RFC2544
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2, documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3, documentation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, and 255.255.255.255
}

// PublicIPv4 reports whether candidate is a dotted quad outside every reserved
// range. It is the fix for a named defect: the inherited pii-ipv4-public rule
// was \b\d{1,3}(?:\.\d{1,3}){3}\b and nothing else, so it flagged 10.0.0.1 and
// 0.0.0.0 despite `public` in its name -- 1,522 matches, the second largest
// source of noise in the corpus. See docs/design/language-choice.md section 3.
//
// Parsing is netip's, which rejects an octet above 255 and rejects a leading
// zero, so 256.1.1.1 and 010.0.0.1 are dropped here rather than treated as
// addresses. The regex that produced the candidate accepts both.
func PublicIPv4(candidate string) bool {
	addr, err := netip.ParseAddr(candidate)
	if err != nil || !addr.Is4() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
