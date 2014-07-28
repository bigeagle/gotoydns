package toydns

import (
	"errors"
	"fmt"
	"net"
	"time"
)

type dnsConn interface {
	ReadPacketFrom() (*dnsMsg, net.Addr, error)
	Read() ([]byte, error)
	WritePacketTo(p *dnsMsg, addr net.Addr) error
	WriteTo(p []byte, addr net.Addr) error
	Write(p []byte) error
	SetReadDeadline(t time.Time) error
	String() string
}

type udpDNSConn struct {
	addr    string
	udpConn *net.UDPConn
}

func listenUDPDNS(addr string) (*udpDNSConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return &udpDNSConn{addr, udpConn}, nil

}

func dialUDPDNS(addr string) (*udpDNSConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return &udpDNSConn{addr, udpConn}, nil
}

func (u *udpDNSConn) Read() ([]byte, error) {
	buf := make([]byte, 512)
	n, err := u.udpConn.Read(buf)
	return buf[:n], err
}

func (u *udpDNSConn) ReadPacketFrom() (*dnsMsg, net.Addr, error) {
	buf := make([]byte, 512)
	n, clientAddr, err := u.udpConn.ReadFromUDP(buf[0:])
	if err != nil {
		logger.Error(err.Error())
		return nil, nil, err

	}

	msg := new(dnsMsg)
	_, err = msg.Unpack(buf[:n], 0)
	if err != nil {
		logger.Error(err.Error())
		return nil, clientAddr, err
	}

	return msg, clientAddr, nil
}

func (u *udpDNSConn) WritePacketTo(p *dnsMsg, addr net.Addr) error {
	pack, err := p.Pack()
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return u.WriteTo(pack, addr)
}

func (u *udpDNSConn) WriteTo(p []byte, addr net.Addr) error {
	_, err := u.udpConn.WriteTo(p, addr)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (u *udpDNSConn) Write(p []byte) error {
	_, err := u.udpConn.Write(p)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (u *udpDNSConn) SetReadDeadline(t time.Time) error {
	return u.udpConn.SetReadDeadline(t)
}

func (u *udpDNSConn) String() string {
	return "dns:" + u.addr
}

type cryptDNSConn struct {
	addr    string
	udpConn *net.UDPConn
	cipher  *dnsCipher
}

func listenCryptDNS(addr string, cipher *dnsCipher) (*cryptDNSConn, error) {
	if cipher == nil {
		return nil, errors.New("Cipher not inited")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return &cryptDNSConn{addr, udpConn, cipher}, nil

}

func dialCryptDNS(addr string, cipher *dnsCipher) (*cryptDNSConn, error) {
	if cipher == nil {
		return nil, errors.New("Cipher not inited")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	return &cryptDNSConn{addr, udpConn, cipher}, nil
}

func (u *cryptDNSConn) ReadPacketFrom() (*dnsMsg, net.Addr, error) {
	buf := make([]byte, 1024)
	n, clientAddr, err := u.udpConn.ReadFromUDP(buf[0:])
	if err != nil {
		logger.Error(err.Error())
		return nil, nil, err

	}

	msg := new(dnsMsg)
	_, err = msg.Unpack(u.cipher.decrypt(buf[:n]), 0)
	if err != nil {
		logger.Error(err.Error())
		return nil, clientAddr, err
	}

	return msg, clientAddr, nil
}

func (u *cryptDNSConn) Read() ([]byte, error) {
	buf := make([]byte, 1024)
	n, err := u.udpConn.Read(buf)
	return u.cipher.decrypt(buf[:n]), err
}

func (u *cryptDNSConn) WritePacketTo(p *dnsMsg, addr net.Addr) error {
	pack, err := p.Pack()
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return u.WriteTo(pack, addr)
}

func (u *cryptDNSConn) WriteTo(p []byte, addr net.Addr) error {
	_, err := u.udpConn.WriteTo(u.cipher.encrypt(p), addr)
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (u *cryptDNSConn) Write(p []byte) error {
	_, err := u.udpConn.Write(u.cipher.encrypt(p))
	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func (u *cryptDNSConn) SetReadDeadline(t time.Time) error {
	return u.udpConn.SetReadDeadline(t)
}

func (u *cryptDNSConn) String() string {
	return "crypt:" + u.addr
}

func listenDNS(e srvEntry) (dnsConn, error) {
	addr := fmt.Sprintf("%s:%d", e.Addr, e.Port)
	switch e.Protocol {
	case PROTO_UDP, PROTO_DNS:
		return listenUDPDNS(addr)
	case PROTO_CRYPT:
		cipher, _ := newCipher([]byte(e.Key))
		return listenCryptDNS(addr, cipher)
	default:
		return nil, errors.New("Undifined Protocol")
	}
}
