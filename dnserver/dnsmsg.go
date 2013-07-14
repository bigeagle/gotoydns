// Justin Wong, modified from go/src/pkg/net/dnsmsg.go
// Copyright 2013 Justin Wong
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toydns

import (
    "bytes"
    "encoding/binary"
    "errors"
    "fmt"
    "strings"
)

var offsetError = errors.New("offset index out of bound")

type dnsHeader struct {
    Id                                 uint16
    Bits                               uint16
    Qdcount, Ancount, Nscount, Arcount uint16
}

func (self *dnsHeader) Unpack(msg []byte, off int) (next int, err error) {
    buf := bytes.NewBuffer(msg[off : off+12])
    err = binary.Read(buf, binary.BigEndian, self)
    if err != nil {
        return len(msg), err
    } else {
        return 12, nil
    }
}

func (self *dnsHeader) Pack() ([]byte, error) {
    buf := new(bytes.Buffer)
    err := binary.Write(buf, binary.BigEndian, self)
    return buf.Bytes(), err
}

type dnsMsgHeader struct {
    id                  uint16
    response            bool
    opcode              int
    authoritative       bool
    truncated           bool
    recursion_desired   bool
    recursion_available bool
    rcode               int
}

func (self *dnsMsgHeader) String() string {
    return fmt.Sprintf(
        "{id: %d, response: %t, opcode: %d, authoritative: %t, "+
            "truncated: %t, RD: %t, RA: %t, rcode: %d}",
        self.id, self.response, self.opcode, self.authoritative, self.truncated,
        self.recursion_desired, self.recursion_available, self.rcode)
}

type dnsMsg struct {
    dnsMsgHeader
    question []dnsQuestion
    answer   []dnsRR
    ns       []dnsRR
    extra    []dnsRR
    names    map[string]int //map name -> offset
}

func (self *dnsMsg) Pack() ([]byte, error) {
    var buf, body bytes.Buffer
    var dh dnsHeader

    if self.names == nil {
        self.names = make(map[string]int)
    }

    nans, nns, nex := 0, 0, 0
    off := 12

    for _, q := range self.question {
        if pack, err := q.Pack(self.names, off); err != nil {
            log.Error(err.Error())
        } else {
            body.Write(pack)
            off += len(pack)
        }
    }

    for _, a := range self.answer {
        //log.Debug(a.String())
        if pack, err := a.Pack(self.names, off); err != nil {
            log.Error(err.Error())
        } else {
            body.Write(pack)
            off += len(pack)
            nans++
        }
    }

    for _, n := range self.ns {
        //log.Debug(n.String())
        if pack, err := n.Pack(self.names, off); err != nil {
            log.Error(err.Error())
        } else {
            body.Write(pack)
            off += len(pack)
            nns++
        }
    }

    for _, e := range self.extra {
        //log.Debug(n.String())
        if pack, err := e.Pack(self.names, off); err != nil {
            log.Error(err.Error())
        } else {
            body.Write(pack)
            off += len(pack)
            nex++
        }
    }

    // Convert convenient dnsMsg into wire-like dnsHeader.
    dh.Id = self.id
    dh.Bits = uint16(self.opcode)<<11 | uint16(self.rcode)
    if self.recursion_available {
        dh.Bits |= _RA
    }
    if self.recursion_desired {
        dh.Bits |= _RD
    }
    if self.truncated {
        dh.Bits |= _TC
    }
    if self.authoritative {
        dh.Bits |= _AA
    }
    if self.response {
        dh.Bits |= _QR
    }

    dh.Qdcount = uint16(len(self.question))
    dh.Ancount = uint16(nans)
    dh.Nscount = uint16(nns)
    dh.Arcount = uint16(nex)

    dh_pack, _ := dh.Pack()
    buf.Write(dh_pack)
    buf.Write(body.Bytes())

    return buf.Bytes(), nil
}

func (self *dnsMsg) Unpack(msg []byte, off int) (next int, err error) {
    var dh dnsHeader

    if off, err = dh.Unpack(msg, 0); err != nil {
        return len(msg), err
    }

    self.id = dh.Id
    self.response = (dh.Bits & _QR) != 0
    self.opcode = int(dh.Bits>>11) & 0xF
    self.authoritative = (dh.Bits & _AA) != 0
    self.truncated = (dh.Bits & _TC) != 0
    self.recursion_desired = (dh.Bits & _RD) != 0
    self.recursion_available = (dh.Bits & _RA) != 0
    self.rcode = int(dh.Bits & 0xF)

    self.question = make([]dnsQuestion, dh.Qdcount)
    self.answer = make([]dnsRR, 0, dh.Ancount)
    self.ns = make([]dnsRR, 0, dh.Nscount)
    self.extra = make([]dnsRR, 0, dh.Arcount)

    for i := uint16(0); i < dh.Qdcount; i++ {
        dq := &self.question[i]
        off, err = dq.Unpack(msg, off)
        if err != nil {
            return len(msg), err
        }
    }

    for i := uint16(0); i < dh.Ancount; i++ {
        var ans dnsRR
        ans, off, err = unpackRR(msg, off)
        if err != nil {
            return len(msg), err
        }
        self.answer = append(self.answer, ans)
    }

    for i := uint16(0); i < dh.Nscount; i++ {
        var ns dnsRR
        ns, off, err = unpackRR(msg, off)
        if err != nil {
            return len(msg), err
        }
        self.ns = append(self.ns, ns)
    }

    for i := uint16(0); i < dh.Arcount; i++ {
        var ex dnsRR
        ex, off, err = unpackRR(msg, off)
        if err != nil {
            return len(msg), err
        }
        self.extra = append(self.extra, ex)
    }

    return len(msg), nil
}

func (self *dnsMsg) Reply() (*dnsMsg, error) {
    rep := new(dnsMsg)

    rep.id = self.id
    rep.authoritative = self.authoritative
    rep.opcode = self.opcode
    rep.rcode = self.rcode
    rep.recursion_available = true
    rep.recursion_desired = self.recursion_desired
    rep.response = true
    rep.truncated = false

    rep.question = self.question

    self.answer = make([]dnsRR, 0, 1)
    self.ns = make([]dnsRR, 0, 0)
    self.extra = make([]dnsRR, 0, 0)

    return rep, nil
}

func (self *dnsMsg) String() string {
    s := "DNS: \n"
    s += "Header: "
    s += self.dnsMsgHeader.String() + "\n"
    s += fmt.Sprintf("%d Questions:\n", len(self.question))
    for _, q := range self.question {
        s += q.String() + "\n"
    }

    s += fmt.Sprintf("%d Answers:\n", len(self.answer))
    for _, a := range self.answer {
        s += a.String() + "\n"
    }

    s += fmt.Sprintf("%d Authorities:\n", len(self.ns))
    for _, a := range self.ns {
        s += a.String() + "\n"
    }

    s += fmt.Sprintf("%d Additional:\n", len(self.extra))
    for _, a := range self.extra {
        s += a.String() + "\n"
    }

    return s
}

// DNS queries.
type dnsQuestion struct {
    Name   string `net:"domain-name"` // `net:"domain-name"` specifies encoding; see packers below
    Qtype  uint16
    Qclass uint16
}

func (self *dnsQuestion) Unpack(msg []byte, off int) (next int, err error) {
    i := off
    if self.Name, i, err = unpackName(msg, i); err != nil {
        return len(msg), err
    }

    if i+4 > len(msg) {
        return len(msg), offsetError
    }

    buf := bytes.NewBuffer(msg[i : i+4])
    binary.Read(buf, binary.BigEndian, &(self.Qtype))
    binary.Read(buf, binary.BigEndian, &(self.Qclass))
    next = i + 4

    return next, nil
}

func (self *dnsQuestion) Pack(names map[string]int, off int) (pack []byte, err error) {

    buf := bytes.NewBuffer([]byte{})

    buf.Write(packName(self.Name, names, off))

    binary.Write(buf, binary.BigEndian, self.Qtype)
    binary.Write(buf, binary.BigEndian, self.Qclass)

    return buf.Bytes(), nil
}

func (self *dnsQuestion) String() string {
    return fmt.Sprintf("{name: %s, qtype: %d, qclass: %d}", self.Name, self.Qtype, self.Qclass)
}

func unpackName(msg []byte, off int) (name string, next int, err error) {
    name = ""
    ptr := 0
    i := off
Loop:
    for {
        if i >= len(msg) {
            return "", len(msg), offsetError
        }
        c := int(msg[i])
        i++
        switch c & 0xC0 {
        case 0x00:
            if c == 0x00 {
                //name end
                break Loop
            }
            if i+c > len(msg) {
                return "", len(msg), offsetError
            }
            name += string(msg[i:i+c]) + "."
            i += c

        // Compressed Record
        case 0xC0:
            if i >= len(msg) {
                return "", len(msg), offsetError
            }
            c1 := msg[i]
            i++
            if ptr == 0 {
                next = i
            }
            if ptr++; ptr > 10 {
                return "", len(msg), offsetError
            }
            i = (c^0xC0)<<8 | int(c1)

        default:
            return "", len(msg), offsetError
        }

    }

    if ptr == 0 {
        next = i
    }
    return name, next, nil
}

func packName(name string, names map[string]int, off int) []byte {
    buf := bytes.NewBuffer([]byte{})

    offset, found := names[name]

    if found {
        binary.Write(buf, binary.BigEndian, uint16(offset)|uint16(0xC0<<8))
    } else {
        names[name] = off
        records := strings.Split(name, ".")
        for _, r := range records {
            buf.WriteByte(byte(len(r)))
            if len(r) > 0 {
                buf.Write([]byte(r))
            }
        }
    }
    return buf.Bytes()
}
