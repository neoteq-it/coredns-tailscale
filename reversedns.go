package tailscale

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

func arpaToIP(qname string) (net.IP, bool) {
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	if strings.HasSuffix(s, "in-addr.arpa") {
		// v4: d.c.b.a.in-addr.arpa
		part := strings.TrimSuffix(s, ".in-addr.arpa")
		oct := strings.Split(part, ".")
		if len(oct) != 4 {
			return nil, false
		}
		// reverse order
		ip := net.ParseIP(fmt.Sprintf("%s.%s.%s.%s", oct[3], oct[2], oct[1], oct[0]))
		if ip == nil {
			return nil, false
		}
		return ip.To4(), true
	}
	if strings.HasSuffix(s, "ip6.arpa") {
		// v6: nibble-reversed hex, e.g. ...f.e.d.c.b.a.9.8.7.6.5.4.3.2.1.0.ip6.arpa
		part := strings.TrimSuffix(s, ".ip6.arpa")
		nibbles := strings.Split(part, ".")
		// Accept any length up to 32 nibbles, but typical is 32
		if len(nibbles) == 0 || len(nibbles) > 32 {
			return nil, false
		}
		// reverse nibbles into a hex string
		var b strings.Builder
		for i := len(nibbles) - 1; i >= 0; i-- {
			if len(nibbles[i]) != 1 {
				return nil, false
			}
			b.WriteString(nibbles[i])
			if (len(nibbles)-i)%4 == 0 && i != 0 {
				// optional: add colon every 4 nibbles for readability (not needed for ParseIP)
			}
		}
		hex := b.String()
		// pad to full 32 nibbles if needed
		if len(hex) < 32 {
			hex = hex + strings.Repeat("0", 32-len(hex))
		}
		ip := parseIPv6Hex(hex)
		if ip == nil {
			return nil, false
		}
		return ip, true
	}
	return nil, false
}

func parseIPv6Hex(h string) net.IP {
	// h: 32 hex chars
	if len(h) != 32 {
		return nil
	}
	var bs [16]byte
	for i := 0; i < 16; i++ {
		byteVal, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil
		}
		bs[i] = byte(byteVal)
	}
	return net.IP(bs[:])
}

func (t *Tailscale) resolvePTR(qname string, msg *dns.Msg) {
	ip, ok := arpaToIP(qname)
	if !ok {
		return
	}
	ipStr := ip.String()

	// Wir brauchen einen FQDN als PTR-Ziel.
	// Variante: Zone aus qname ableiten ist nicht möglich; nimm daher die Zone,
	// die dein Plugin ohnehin kennt (z.B. t.zone: "ntqnet.com.").
	zone := t.zone
	if zone == "" {
		zone = "local." // Fallback, besser: korrekt in der Tailscale-Plugin-Init setzen
	}
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	// Durchsuche alle Hosts, ob A/AAAA die IP enthalten.
	for hostShort, rrmap := range t.entries {
		if addrs, ok := rrmap["A"]; ok {
			for _, a := range addrs {
				if a == ipStr {
					fqdn := hostShort + "." + zone
					msg.Answer = append(msg.Answer, &dns.PTR{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
						Ptr: fqdn,
					})
				}
			}
		}
		if addrs, ok := rrmap["AAAA"]; ok {
			for _, a := range addrs {
				if a == ipStr {
					fqdn := hostShort + "." + zone
					msg.Answer = append(msg.Answer, &dns.PTR{
						Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 60},
						Ptr: fqdn,
					})
				}
			}
		}
	}
}
