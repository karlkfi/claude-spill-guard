package validate

import (
	"net/netip"
	"testing"
)

// pii-ipv4-public produced 1,522 matches on the corpus and every one was a
// reserved address. The negative table below is that defect, case by case.
func TestPublicIPv4(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		want      bool
	}{
		{"a public resolver", "8.8.8.8", true},
		{"another public resolver", "1.1.1.1", true},
		{"the byte below RFC1918", "9.255.255.255", true},
		{"the byte above RFC1918", "11.0.0.0", true},
		{"the byte below the 172.16 block", "172.15.255.255", true},
		{"the byte above the 172.16 block", "172.32.0.0", true},
		{"the byte below TEST-NET-1", "192.0.1.255", true},
		{"the byte above TEST-NET-3", "203.0.114.0", true},
		{"the byte below multicast", "223.255.255.255", true},

		{"the unspecified address", "0.0.0.0", false},
		{"RFC1918, the address the inherited rule flagged", "10.0.0.1", false},
		{"RFC1918, a cluster service address from the corpus", "10.233.0.1", false},
		{"RFC1918, the 172.16 block", "172.16.0.1", false},
		{"RFC1918, the 192.168 block", "192.168.1.1", false},
		{"loopback", "127.0.0.1", false},
		{"link-local", "169.254.169.254", false},
		{"carrier-grade NAT", "100.64.0.1", false},
		{"IETF protocol assignments", "192.0.0.1", false},
		{"TEST-NET-1, the documentation range", "192.0.2.1", false},
		{"TEST-NET-2, the documentation range", "198.51.100.1", false},
		{"TEST-NET-3, the documentation range", "203.0.113.1", false},
		{"6to4 relay anycast", "192.88.99.1", false},
		{"benchmarking", "198.18.0.1", false},
		{"multicast", "224.0.0.1", false},
		{"the reserved class E block", "240.0.0.1", false},
		{"the broadcast address", "255.255.255.255", false},

		{"an octet above 255, which the rule's regex accepts", "256.1.1.1", false},
		{"a leading zero, which the rule's regex accepts", "010.0.0.1", false},
		{"a trailing leading zero", "1.2.3.04", false},
		{"three octets", "1.2.3", false},
		{"five octets", "1.2.3.4.5", false},
		{"an empty candidate", "", false},
		{"IPv6 loopback", "::1", false},
		{"a v4-mapped v6 address, which is not a dotted quad", "::ffff:8.8.8.8", false},
		{"a dotted version string", "6.16.13.30300400", false},
		{"an address with a port", "8.8.8.8:53", false},
		{"an address with a zone", "8.8.8.8%eth0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := PublicIPv4(tc.candidate); got != tc.want {
				t.Errorf("PublicIPv4(%q) = %v, want %v", tc.candidate, got, tc.want)
			}
		})
	}
}

// Every prefix in the table must exclude something. A typo that narrows one to
// a single address leaves the other cases passing and the range open, which is
// the shape of the bug this validator exists to fix.
func TestEveryReservedPrefixExcludesItsOwnBounds(t *testing.T) {
	for _, p := range reserved {
		lo := p.Masked().Addr()
		if PublicIPv4(lo.String()) {
			t.Errorf("PublicIPv4(%q) = true, but %v is the first address of a reserved prefix", lo, p)
		}
		// The last address of the prefix, reached by setting every host bit.
		last := lo.As4()
		host := 32 - p.Bits()
		for i := 0; i < host; i++ {
			last[3-i/8] |= 1 << (i % 8)
		}
		if hi := netip.AddrFrom4(last); PublicIPv4(hi.String()) {
			t.Errorf("PublicIPv4(%q) = true, but %v is the last address of a reserved prefix", hi, p)
		}
	}
}
