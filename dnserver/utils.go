package toydns

import (
    "bytes"
)

var _AAAABlackList = []([]byte){
    []byte{32, 1, 13, 168, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 33, 174},
}

var _ABlackList = []uint32{
    0,          // 0.0.0.0
    0x01010101, // 1.1.1.1
    0xFFFFFFFF, // 255.255.255.255
    ip2int(37, 61, 54, 158),
    ip2int(203, 98, 7, 65),
    ip2int(93, 46, 8, 89),
    ip2int(59, 24, 3, 173),
}

func ip2int(a, b, c, d int) uint32 {
    return uint32((a << 24) + (b << 16) + (c << 8) + d)
}

func gfwPolluted(d *dnsMsg) bool {
	if len(d.question) < 1 {
		return false
	}
    q := d.question[0]
    //log.Debug("%v", d)
    // Now only AAAA pollution is supported

    switch int(q.Qtype) {
    case dnsTypeAAAA:
        if len(d.answer) > 0 {
            for _, ans := range d.answer {
                if aaaa, ok := ans.Rdata().([16]byte); ok {
                    //log.Debug("%v", aaaa)
                    if aaaa[0] == byte(0) {
                        return true
                    }
                    for _, black := range _AAAABlackList {
                        if bytes.Compare(aaaa[:], black) == 0 {
                            return true
                        }
                    }
                    count := 0
                    for _, b := range aaaa {
                        if b == byte(0) {
                            count++
                        }
                    }
                    if count > 11 {
                        return true
                    }

                }
            }
        }
    case dnsTypeA:
        if len(d.answer) > 0 {
            for _, ans := range d.answer {
                if a, ok := ans.Rdata().(uint32); ok {
                    //log.Debug("%v", aaaa)
                    for _, black := range _ABlackList {
                        if a == black {
                            return true
                        }
                    }
                }
            }
        }

    }

    return false
}
