package toydns

import (
	"errors"
	"fmt"
)

type upstreamEntry struct {
	protocol string
	udpAddr  string
	cipher   *dnsCipher
}

func newUpstreamEntry(entry interface{}) *upstreamEntry {
	switch e := entry.(type) {
	case string:
		return &upstreamEntry{
			protocol: PROTO_DNS,
			udpAddr:  e,
			cipher:   nil,
		}
	case srvEntry:
		var cipher *dnsCipher = nil
		addr := fmt.Sprintf("%s:%d", e.Addr, e.Port)
		if e.Protocol == PROTO_CRYPT && e.Key != "" {
			cipher, _ = newCipher([]byte(e.Key))
		}
		return &upstreamEntry{
			protocol: e.Protocol,
			udpAddr:  addr,
			cipher:   cipher,
		}
	default:
		return nil
	}

}

func dialUpstream(e *upstreamEntry) (dnsConn, error) {
	switch e.protocol {
	case PROTO_DNS, PROTO_UDP:
		return dialUDPDNS(e.udpAddr)
	case PROTO_CRYPT:
		return dialCryptDNS(e.udpAddr, e.cipher)
	default:
		return nil, errors.New("Undifined Protocol")
	}
}
