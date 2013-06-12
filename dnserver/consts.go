package toydns

const (
    // valid dnsRR_Header.Rrtype and dnsQuestion.qtype
    dnsTypeA     = 1
    dnsTypeNS    = 2
    dnsTypeMD    = 3
    dnsTypeMF    = 4
    dnsTypeCNAME = 5
    dnsTypeSOA   = 6
    dnsTypeMB    = 7
    dnsTypeMG    = 8
    dnsTypeMR    = 9
    dnsTypeNULL  = 10
    dnsTypeWKS   = 11
    dnsTypePTR   = 12
    dnsTypeHINFO = 13
    dnsTypeMINFO = 14
    dnsTypeMX    = 15
    dnsTypeTXT   = 16
    dnsTypeAAAA  = 28
    dnsTypeSRV   = 33
    dnsTypeOPT   = 41

    // valid dnsQuestion.qtype only
    dnsTypeAXFR  = 252
    dnsTypeMAILB = 253
    dnsTypeMAILA = 254
    dnsTypeALL   = 255

    // valid dnsQuestion.qclass
    dnsClassINET   = 1
    dnsClassCSNET  = 2
    dnsClassCHAOS  = 3
    dnsClassHESIOD = 4
    dnsClassANY    = 255

    // dnsMsg.rcode
    dnsRcodeSuccess        = 0
    dnsRcodeFormatError    = 1
    dnsRcodeServerFailure  = 2
    dnsRcodeNameError      = 3
    dnsRcodeNotImplemented = 4
    dnsRcodeRefused        = 5
)

const (
    // dnsHeader.Bits
    _QR = 1 << 15 // query/response (response=1)
    _AA = 1 << 10 // authoritative
    _TC = 1 << 9  // truncated
    _RD = 1 << 8  // recursion desired
    _RA = 1 << 7  // recursion available
)

var _dnsTypeString map[uint16]string = map[uint16]string{
    uint16(1):  "A",
    uint16(2):  "NS",
    uint16(3):  "MD",
    uint16(4):  "MF",
    uint16(5):  "CNAME",
    uint16(6):  "SOA",
    uint16(7):  "MB",
    uint16(8):  "MG",
    uint16(9):  "MR",
    uint16(10): "NULL",
    uint16(11): "WKS",
    uint16(12): "PTR",
    uint16(13): "HINFO",
    uint16(14): "MINFO",
    uint16(15): "MX",
    uint16(16): "TXT",
    uint16(28): "AAAA",
    uint16(33): "SRV",
    uint16(41): "OPT",
}

func dnsTypeString(dnstype uint16) string {
    s, ok := _dnsTypeString[dnstype]
    if ok {
        return s
    } else {
        return "UNKNOWN"
    }
}
