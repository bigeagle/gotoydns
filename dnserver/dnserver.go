package toydns

import (
    "net"
    "errors"
    "time"
    "math/rand"
    "github.com/howeyc/fsnotify"
    "sync"
)

var log logger

var _rdblock sync.RWMutex

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
    rdb *domainDB
    cache *dnsCache
    //upstream *net.UDPConn
}

func NewServer(port string, upstream string, recordfile string, _log logger) (*DNSServer, error) {
    dns := &DNSServer{}
    log = _log
    if err := dns.initServer(port, upstream, recordfile); err != nil {
        return nil, err
    }
    return dns, nil
}


func (self *DNSServer) initServer(port string, upstream string, recordfile string) error {

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

    self.rdb = nil
    if recordfile != "" {

        fatal := func(err error) {
            if log != nil {
                log.Fatal(err)
            }
        }

        readDB := func() {
            db, err := readRecordsFile(recordfile)
            if err == nil {
                _rdblock.Lock()
                self.rdb = db
                _rdblock.Unlock()
            }
        }
        readDB()

        //Watch record file modify and update record db
        watcher, err := fsnotify.NewWatcher()
        if err != nil {
            fatal(err)
            return err
        }

        err = watcher.Watch(recordfile)
        if err != nil {
            fatal(err)
            return err
        }
        go func() {
            for {
                select {
                case ev := <-watcher.Event:
                    if ev.IsModify() {
                        readDB()
                        if log != nil {
                            log.Info("record file updated")
                        }
                    }
                case err := <-watcher.Error:
                    fatal(err)
                }
            }
        }()
    }

    self.cache = newDNSCache()


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

    dnsq := new(dnsMsg)
    _, err := dnsq.Unpack(msg, 0)
    if err != nil {
        if log != nil {
            log.Error(err.Error())
        }
        return
    }
    qid := dnsq.id

    //try cache
    cpack, found := self.cache.Get(dnsq.question[0].Name, int(dnsq.question[0].Qtype))
    if found {
        cpack[0] = byte(qid >> 8)
        cpack[1] = byte(qid)
        if log != nil {
            log.Info("Query %s[%s] from %s [HIT]",
                dnsq.question[0].Name,
                dnsTypeString(dnsq.question[0].Qtype),
                clientAddr.String())
        }
        self.udpConn.WriteTo(cpack, clientAddr)
        return
    }

    if log != nil {
        log.Info("Query %s[%s] from %s [MISS]",
            dnsq.question[0].Name,
            dnsTypeString(dnsq.question[0].Qtype),
            clientAddr.String())
    }

    //try local look up
    dnsmsg, _ := dnsq.Reply()
    if len(dnsmsg.question) == 1 && self.rdb != nil {
        q := dnsmsg.question[0]
        ans := make([]dnsRR, 0, 10)
        _rdblock.RLock()
        found := queryDB(q.Name, int(q.Qtype), self.rdb, &ans)
        _rdblock.RUnlock()
        if found {
            dnsmsg.answer = ans
            pack, _ := dnsmsg.Pack()
            if log != nil {
                log.Debug(dnsmsg.String())
            }
            self.udpConn.WriteTo(pack, clientAddr)
            self.cache.Insert(q.Name, int(q.Qtype), pack, int(ans[0].Header().Ttl))
            return
        }
    }

    // give it to upstream
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
            localchan <- msg
        }
    }(upsockchan)


    for {
        select {
            case cltMsg := <-self.upchan:
                upConn.Write(cltMsg)

            case upMsg := <-upsockchan:
                if len(upMsg) < 12 {
                    continue
                }
                rid := uint16(upMsg[0]) << 8 + uint16(upMsg[1])

                client, ok := self.cltMap[rid]
                if !ok {
                    continue
                }
                delete(self.cltMap, rid)

                qid := client.dq_id
                upMsg[0] = byte(qid >> 8)
                upMsg[1] = byte(qid)

                if log != nil {
                    log.Debug("rid: %d, qid: %d", rid, qid)
                }

                // insert to cache
                go func(msg []byte) {
                    dnsmsg := new(dnsMsg)
                    _, err := dnsmsg.Unpack(msg, 0)
                    if err != nil {
                        if log != nil {
                            log.Error(err.Error())
                        }
                        return
                    }
                    q := dnsmsg.question[0]
                    if len(dnsmsg.answer) > 0 {
                        if log != nil {
                            log.Debug("%s:%d", q.Name, q.Qtype)
                        }
                        self.cache.Insert(
                            q.Name, int(q.Qtype), msg,
                            int(dnsmsg.answer[0].Header().Ttl))
                    } else {
                        if log != nil {
                            log.Debug(dnsmsg.String())
                        }
                        self.cache.Insert(
                            q.Name, int(q.Qtype), msg, 10)
                    }
                }(upMsg)


                self.udpConn.WriteTo(upMsg, client.addr)
        }

    }

}
