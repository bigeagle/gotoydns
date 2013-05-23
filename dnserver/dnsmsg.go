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
	"net"
)

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
    names    map[string] int //map name -> offset
}

func (self *dnsMsg) Pack() ([]byte, error) {
    var buf bytes.Buffer
	var dh dnsHeader

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

	question := self.question
	answer := self.answer
	ns := self.ns
	extra := self.extra

	dh.Qdcount = uint16(len(question))
	dh.Ancount = uint16(len(answer))
	dh.Nscount = uint16(len(ns))
	dh.Arcount = uint16(len(extra))

    dh_pack, _ := dh.Pack()
    buf.Write(dh_pack)

    if self.names == nil {
        self.names = make(map[string] int)
    }

    off := len(dh_pack)
    for _, q := range question {
        pack, _ := q.Pack(self.names, off)
        buf.Write(pack)
        off += len(pack)
    }

    for _, a := range answer {
        log.Debug(a.String())
        pack, _ := a.Pack(self.names, off)
        buf.Write(pack)
        off += len(pack)
    }

    for _, n := range ns {
        log.Debug(n.String())
        pack, _ := n.Pack(self.names, off)
        buf.Write(pack)
        off += len(pack)
    }

    //for _, e := range extra {
    //    log.Debug(e.String())
    //    pack, _ := e.Pack(self.names, off)
    //    buf.Write(pack)
    //    off += len(pack)
    //}

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
	}

	for i := uint16(0); i < dh.Ancount; i++ {
		var ans dnsRR
		ans, off, err = unpackRR(msg, off)
		self.answer = append(self.answer, ans)
	}

	for i := uint16(0); i < dh.Nscount; i++ {
		var ns dnsRR
		ns, off, err = unpackRR(msg, off)
		self.ns = append(self.ns, ns)
	}

	for i := uint16(0); i < dh.Arcount; i++ {
		var ex dnsRR
		ex, off, err = unpackRR(msg, off)
		self.extra = append(self.extra, ex)
	}

	return len(msg), nil
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

	s += fmt.Sprintf("%d Authorities:\n", len(self.answer))
	for _, a := range self.ns {
		s += a.String() + "\n"
	}

	s += fmt.Sprintf("%d Additional:\n", len(self.answer))
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

var rr_mk = map[int]func() dnsRR{
	dnsTypeCNAME: func() dnsRR { return new(dnsRR_CNAME) },
	dnsTypeA:     func() dnsRR { return new(dnsRR_A) },
}

type dnsRR interface {
	setHeader(*dnsRR_Header)
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

func (self *dnsRR_unknown) setHeader(header *dnsRR_Header) {
	self.Hdr = header
}

func (self *dnsRR_unknown) String() string {
	header := self.Hdr
	return fmt.Sprintf("{name: %s, TTL: %d, class: %d, type: UNKNOWN, rdata: % x}",
		header.Name, header.Ttl, header.Class, self.rawRdata)
}

func (self *dnsRR_unknown) unpackRdata(msg []byte, off int) {
	self.rawRdata = msg[off:]
}


func (self *dnsRR_unknown) Pack(names map[string] int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    buf.Write(self.rawRdata)
    return buf.Bytes(), nil
}

type dnsRR_A struct {
	dnsRR_unknown
	A uint32 `net:"ipv4"`
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

func (self *dnsRR_A) Pack(names map[string] int, off int) ([]byte, error) {
    buf, _ := self.Hdr.Pack(names, off)
    binary.Write(buf, binary.BigEndian, self.A)
    return buf.Bytes(), nil
}

type dnsRR_CNAME struct {
	dnsRR_unknown
	CNAME string
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

func (self *dnsRR_CNAME) Pack(names map[string] int, off int) ([]byte, error) {
    buf := bytes.NewBuffer([]byte{})
    namePack := packName(self.Hdr.Name, names, off)
    buf.Write(namePack)
    off += 10 + len(namePack)

    cnamePack := packName(self.CNAME, names, off)

    self.Hdr.Rdlength = uint16(len(cnamePack))

    var data = []interface{} {
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
	rr.unpackRdata(msg[:next], i)
	return rr, next, nil
}

func unpackName(msg []byte, off int) (name string, next int, err error) {
	name = ""
	ptr := 0
	i := off
	err = errors.New("offset error")
Loop:
	for {
		if i > len(msg) {
			return "", len(msg), err
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
				return "", len(msg), err
			}
			name += string(msg[i:i+c]) + "."
			i += c

		// Compressed Record
		case 0xC0:
			if i >= len(msg) {
				return "", len(msg), err
			}
			c1 := msg[i]
			i++
			if ptr == 0 {
				next = i
			}
			if ptr++; ptr > 10 {
				return "", len(msg), err
			}
			i = (c^0xC0)<<8 | int(c1)

		default:
			return "", len(msg), err
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
        binary.Write(buf, binary.BigEndian, uint16(offset) | uint16(0xC0 << 8))
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
