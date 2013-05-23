package toydns

import (
    "net"
    "errors"
    "time"
    "math/rand"
)

var log logger

type dnsClient struct {
    addr net.Addr
    dq_id uint16
}

type random struct {
    R *rand.Rand
}


func (self *random) Uint16() uint16 {
    return uint16(self.R.Int31n(65535))
}

type DNSServer struct {
    udpConn *net.UDPConn
    r *random
    cltMap map[uint16] *dnsClient
    upchan chan []byte
    //upstream *net.UDPConn
}

func NewServer(port string, upstream string, _log logger) *DNSServer {
    dns := &DNSServer{}
    log = _log
    dns.initServer(port, upstream)
    return dns
}


func (self *DNSServer) initServer(port string, upstream string) error {

    udpAddr, err := net.ResolveUDPAddr("udp", port)
    if err != nil {
        return err
    }

    udpConn, err := net.ListenUDP("udp", udpAddr)
    if err != nil {
        return err
    }

    self.udpConn = udpConn

    if log != nil {
        log.Info("Start Listening on port %s", port)
    }

    r := new(random)
    r.R = rand.New(rand.NewSource(time.Now().Unix()))
    self.r = r
    self.cltMap = make(map[uint16] *dnsClient)

    self.upchan = make(chan []byte, 32)

    go self.handleUpstream(upstream)

    return nil
}

func (self *DNSServer) ServeForever() error {

    for {
        buf := make([]byte, 512)
        n, clientAddr, _ := self.udpConn.ReadFrom(buf[0:])
        go self.handleClient(buf[:n], clientAddr)
    }

    return errors.New("Here should not be reached")
}


func (self *DNSServer) handleClient(msg []byte, clientAddr net.Addr) {

    if log != nil {
        log.Debug(clientAddr.String())
    }


    qid := uint16(msg[0]) << 8 + uint16(msg[1])
    rid := self.r.Uint16()

    self.cltMap[rid] = &dnsClient{addr: clientAddr, dq_id: qid}

    msg[0] = byte(rid >> 8)
    msg[1] = byte(rid)

    if log != nil {
        log.Debug("qid: %d, rid: %d", qid, rid)
    }

    self.upchan <- msg
}

func (self *DNSServer) handleUpstream(upstream string) {
    upAddr, _ := net.ResolveUDPAddr("udp", upstream)
    upConn, _ := net.DialUDP("udp", nil, upAddr)

    upsockchan := make(chan []byte, 32)

    go func(localchan chan[]byte) {
        for {
            buf := make([]byte, 2048)
            n, _ := upConn.Read(buf)
            msg := buf[:n]

            dnsmsg := new(dnsMsg)
            dnsmsg.Unpack(msg, 0)

            log.Debug(dnsmsg.String())

            localchan <- msg
        }
    }(upsockchan)


    for {
        select {
            case cltMsg := <-self.upchan:
                upConn.Write(cltMsg)

            case upMsg := <-upsockchan:
                rid := uint16(upMsg[0]) << 8 + uint16(upMsg[1])

                client := self.cltMap[rid]
                delete(self.cltMap, rid)

                qid := client.dq_id
                upMsg[0] = byte(qid >> 8)
                upMsg[1] = byte(qid)

                if log != nil {
                    log.Debug("rid: %d, qid: %d", rid, qid)
                }

                self.udpConn.WriteTo(upMsg, client.addr)
        }

    }

}
