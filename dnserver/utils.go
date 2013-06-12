package toydns

import (
    "bytes"
)

var _AAAABlackList = []([]byte){
    []byte{32, 1, 13, 168, 1, 18, 0, 0, 0, 0, 0, 0, 0, 0, 33, 174},
}

func gfwPolluted(d *dnsMsg) bool {
    q := d.question[0]
    //log.Debug("%v", d)
    // Now only AAAA pollution is supported
    if q.Qtype == uint16(dnsTypeAAAA) {
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

    }
    return false
}
