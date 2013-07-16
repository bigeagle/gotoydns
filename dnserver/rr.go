package toydns

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "net"
)

var rr_mk = map[int]func() dnsRR{
    dnsTypeCNAME: func() dnsRR { return new(dnsRR_CNAME) },
    dnsTypeA:     func() dnsRR { return new(dnsRR_A) },
    dnsTypeAAAA:  func() dnsRR { return new(dnsRR_AAAA) },
    dnsTypeNS:    func() dnsRR { return new(dnsRR_NS) },
    dnsTypeOPT:   func() dnsRR { return new(dnsRR_OPT) },
}

type dnsRR interface {
    Header() *dnsRR_Header
    Rdata() interface{}
    setHeader(*dnsRR_Header)
    setRdata(data interface{}) error
    unpackRdata([]byte, int)
    Pack(names map[string]int, off int) ([]byte, error)
    String() string
}

// DNS responses (resource records).
// There are many types of messages,
// but they all share the same header.
type dnsRR_Header struct {
    Name     string `net:"domain-name"`
    Rrtype   uint16
    Class    uint16
    Ttl      uint32
    Rdlength uint16 // length of data after header
}

func (self *dnsRR_Header) Unpack(msg []byte, off int) (next int, err error) {
    i := off

    if self.Name, i, err = unpackName(msg, i); err != nil {
        return len(msg), err
    }
    if i+10 > len(msg) {
        return len(msg), offsetError
    }

    buf := bytes.NewBuffer(msg[i : i+10])

    binary.Read(buf, binary.BigEndian, &(self.Rrtype))
    binary.Read(buf, binary.BigEndian, &(self.Class))
    binary.Read(buf, binary.BigEndian, &(self.Ttl))
    binary.Read(buf, binary.BigEndian, &(self.Rdlength))

    next = i + 10

    return next, nil
}

func (self *dnsRR_Header) Pack(names map[string]int, off int) (*bytes.Buffer, error) {
    buf := bytes.NewBuffer([]byte{})

    buf.Write(packName(self.Name, names, off))

    var data = []interface{}{
        self.Rrtype,
        self.Class,
        self.Ttl,
        self.Rdlength,
    }

    for _, v := range data {
        binary.Write(buf, binary.BigEndian, v)
    }

    return buf, nil

}

type dnsRR_unknown struct {
    Hdr      *dnsRR_Header
    rawRdata []byte
}

func (self *dnsRR_unknown) Header() *dnsRR_Header {
    return self.Hdr
}

func (self *dnsRR_unknown) Rdata() interface{} {
    return self.rawRdata
}

func (self *dnsRR_unknown) setHeader(header *dnsRR_Header) {
    self.Hdr = header
}

func (self *dnsRR_unknown) setRdata(data interface{}) error {
    switch v := data.(type) {
    case []byte:
        self.rawRdata = v
    case string:
        self.rawRdata = []byte(v)
    case bytes.Buffer:
        self.rawRdata = v.Bytes()
    default:
        return fmt.Errorf("Unsupported type")
    }
    return nil
}

func (self *dnsRR_unknown) String() string {
    header := self.Hdr
    return fmt.Sprintf("{name: %s, TTL: %d, class: %d, type: UNKNOWN, rdata: % x}",
        header.Name, header.Ttl, header.Class, self.rawRdata)
}

func (self *dnsRR_unknown) unpackRdata(msg []byte, off int) {
    self.rawRdata = msg[off:]
}

func (self *dnsRR_unknown) Pack(names map[string]int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    buf.Write(self.rawRdata)
    return buf.Bytes(), fmt.Errorf("unknown RR type: %d", self.Hdr.Rrtype)
}

//A
type dnsRR_A struct {
    dnsRR_unknown
    A   uint32 `net:"ipv4"`
}

func (self *dnsRR_A) Rdata() interface{} {
    return self.A
}

func (self *dnsRR_A) unpackRdata(msg []byte, off int) {
    buf := bytes.NewBuffer(msg[off : off+4])
    binary.Read(buf, binary.BigEndian, &self.A)
}

func (self *dnsRR_A) String() string {
    header := self.Hdr
    return fmt.Sprintf(
        "{name: %s, TTL: %d, class: %d, type: A, rdata: %s}",
        header.Name, header.Ttl, header.Class,
        net.IPv4(byte(self.A>>24), byte(self.A>>16), byte(self.A>>8), byte(self.A)).String())
}

func (self *dnsRR_A) Pack(names map[string]int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    binary.Write(buf, binary.BigEndian, self.A)
    return buf.Bytes(), nil
}

func (self *dnsRR_A) setRdata(data interface{}) error {
    toInt32 := func(ip net.IP) uint32 {
        buf := bytes.NewBuffer(ip.To4()[0:4])
        uint32Ip := uint32(0)
        binary.Read(buf, binary.BigEndian, &uint32Ip)
        return uint32Ip
    }
    self.Hdr.Rdlength = uint16(4)
    switch v := data.(type) {
    case net.IP:
        self.A = toInt32(v)
    case string:
        self.A = toInt32(net.ParseIP(v))
    case uint32:
        self.A = v
    default:
        return fmt.Errorf("Unsupported type")
    }
    return nil
}

//AAAA
type dnsRR_AAAA struct {
    dnsRR_unknown
    AAAA [16]byte `net:"ipv6"`
}

func (self *dnsRR_AAAA) Rdata() interface{} {
    return self.AAAA
}

func (self *dnsRR_AAAA) unpackRdata(msg []byte, off int) {
    buf := bytes.NewBuffer(msg[off : off+16])
    buf.Read(self.AAAA[:])
}

func (self *dnsRR_AAAA) String() string {
    header := self.Hdr
    return fmt.Sprintf(
        "{name: %s, TTL: %d, class: %d, type: AAAA, rdata: %s}",
        header.Name, header.Ttl, header.Class,
        net.IP(self.AAAA[:]).String())
}

func (self *dnsRR_AAAA) Pack(names map[string]int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    buf.Write(self.AAAA[:])
    return buf.Bytes(), nil
}

func (self *dnsRR_AAAA) setRdata(data interface{}) error {

    self.Hdr.Rdlength = uint16(16)

    switch v := data.(type) {
    case net.IP:
        if len(v) == net.IPv6len {
            for i, x := range v {
                self.AAAA[i] = x
            }
            return nil
        }
    case string:
        if ip := net.ParseIP(v); ip != nil {
            if len(ip) == net.IPv6len {
                for i, x := range ip {
                    self.AAAA[i] = x
                }
                return nil
            }
        }
    }
    return fmt.Errorf("Unsupported type")
}

//CNAME
type dnsRR_CNAME struct {
    dnsRR_unknown
    CNAME string
}

func (self *dnsRR_CNAME) Rdata() interface{} {
    return self.CNAME
}

func (self *dnsRR_CNAME) unpackRdata(msg []byte, off int) {
    self.CNAME, _, _ = unpackName(msg, off)
}

func (self *dnsRR_CNAME) String() string {
    header := self.Hdr
    return fmt.Sprintf(
        "{name: %s, TTL: %d, class: %d, type: CNAME, rdata: %s}",
        header.Name, header.Ttl, header.Class, self.CNAME)
}

func (self *dnsRR_CNAME) Pack(names map[string]int, off int) ([]byte, error) {
    buf := bytes.NewBuffer([]byte{})
    namePack := packName(self.Hdr.Name, names, off)
    buf.Write(namePack)
    off += 10 + len(namePack)

    cnamePack := packName(self.CNAME, names, off)

    self.Hdr.Rdlength = uint16(len(cnamePack))

    var data = []interface{}{
        self.Hdr.Rrtype,
        self.Hdr.Class,
        self.Hdr.Ttl,
        self.Hdr.Rdlength,
    }

    for _, v := range data {
        binary.Write(buf, binary.BigEndian, v)
    }

    buf.Write(cnamePack)
    return buf.Bytes(), nil
}

func (self *dnsRR_CNAME) setRdata(data interface{}) error {

    switch v := data.(type) {
    case string:
        self.CNAME = v
    case []byte:
        self.CNAME = string(v)
    default:
        return fmt.Errorf("Unsupported type")
    }
    return nil

}

//NS
type dnsRR_NS struct {
    dnsRR_unknown
    NS  string
}

func (self *dnsRR_NS) Rdata() interface{} {
    return self.NS
}

func (self *dnsRR_NS) unpackRdata(msg []byte, off int) {
    self.NS, _, _ = unpackName(msg, off)
}

func (self *dnsRR_NS) String() string {
    header := self.Hdr
    return fmt.Sprintf(
        "{name: %s, TTL: %d, class: %d, type: NS, rdata: %s}",
        header.Name, header.Ttl, header.Class, self.NS)
}

func (self *dnsRR_NS) Pack(names map[string]int, off int) ([]byte, error) {
    buf := bytes.NewBuffer([]byte{})
    namePack := packName(self.Hdr.Name, names, off)
    buf.Write(namePack)
    off += 10 + len(namePack)

    nsPack := packName(self.NS, names, off)

    self.Hdr.Rdlength = uint16(len(nsPack))

    var data = []interface{}{
        self.Hdr.Rrtype,
        self.Hdr.Class,
        self.Hdr.Ttl,
        self.Hdr.Rdlength,
    }

    for _, v := range data {
        binary.Write(buf, binary.BigEndian, v)
    }

    buf.Write(nsPack)
    return buf.Bytes(), nil
}

func (self *dnsRR_NS) setRdata(data interface{}) error {

    switch v := data.(type) {
    case string:
        self.NS = v
    case []byte:
        self.NS = string(v)
    default:
        return fmt.Errorf("Unsupported type")
    }
    return nil

}

//OPT
type dnsRR_OPT struct {
    dnsRR_unknown
    rawRdata []byte
}

func (self *dnsRR_OPT) String() string {
    header := self.Hdr
    return fmt.Sprintf("{name: %s, TTL: %d, class: %d, type: OPT, rdata: % x}",
        header.Name, header.Ttl, header.Class, self.rawRdata)
}

func (self *dnsRR_OPT) unpackRdata(msg []byte, off int) {
    self.rawRdata = msg[off:]
}

func (self *dnsRR_OPT) Pack(names map[string]int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    buf.Write(self.rawRdata)
    return buf.Bytes(), nil
}

func unpackRR(msg []byte, off int) (rr dnsRR, next int, err error) {
    i := off
    header := new(dnsRR_Header)

    if i, err = header.Unpack(msg, off); err != nil {
        return nil, len(msg), err
    }

    mk, known := rr_mk[int(header.Rrtype)]

    if !known {
        rr = new(dnsRR_unknown)
    } else {
        rr = mk()
    }

    next = i + int(header.Rdlength)
    rr.setHeader(header)
    if next > len(msg) {
        return nil, len(msg), fmt.Errorf("Rdlength %d larger than message length %d", next, len(msg))
    }
    rr.unpackRdata(msg[:next], i)
    return rr, next, nil
}

func newRR(name string, rrtype int, ttl int, data interface{}) (dnsRR, error) {
    header := new(dnsRR_Header)
    header.Name = name
    header.Ttl = uint32(ttl)
    header.Rrtype = uint16(rrtype)
    header.Class = dnsClassINET

    var rr dnsRR
    mk, known := rr_mk[int(header.Rrtype)]

    if !known {
        rr = new(dnsRR_unknown)
        //rr.s
    } else {
        rr = mk()
    }

    rr.setHeader(header)

    err := rr.setRdata(data)

    if err != nil {
        return nil, err
    }

    return rr, nil
}
