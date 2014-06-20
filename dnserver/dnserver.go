package toydns

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/howeyc/fsnotify"
)

var logger _Logger

var _rdblock sync.RWMutex

type random struct {
	R *rand.Rand
}

func (self *random) Uint16() uint16 {
	return uint16(self.R.Int31n(65535))
}

type DNSServer struct {
	udpConn *net.UDPConn
	r       *random
	rdb     *domainDB
	cache   *dnsCache
	//upstream *net.UDPConn
	upstreams []string
}

var defaultUpChan = make(chan []byte, 32)

func NewServer(port string, upstream string, recordfile string, _log _Logger) (*DNSServer, error) {
	dns := &DNSServer{}
	if _log == nil {
		return nil, errors.New("No logger specified")
	}
	logger = _log
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

	logger.Info("Start Listening on port %s", port)

	self.rdb = nil
	if recordfile != "" {

		fatal := func(err error) {
			logger.Fatal(err)
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
						logger.Info("record file updated")
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
	self.upstreams = strings.Split(upstream, ",")

	return nil
}

func (self *DNSServer) ServeForever() error {

	for {
		buf := make([]byte, 512)
		n, clientAddr, _ := self.udpConn.ReadFromUDP(buf[0:])
		go self.handleClient(buf[:n], clientAddr)
	}

	return errors.New("Here should not be reached")
}

func (self *DNSServer) handleClient(msg []byte, clientAddr *net.UDPAddr) {
	dnsq := new(dnsMsg)
	_, err := dnsq.Unpack(msg, 0)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	qid := dnsq.id

	//try cache
	cpack, found := self.cache.Get(dnsq.question[0].Name, int(dnsq.question[0].Qtype))
	if found {
		cpack[0] = byte(qid >> 8)
		cpack[1] = byte(qid)
		logger.Info("Query %s[%s] from %s [HIT]",
			dnsq.question[0].Name,
			dnsTypeString(dnsq.question[0].Qtype),
			clientAddr.String())
		self.udpConn.WriteTo(cpack, clientAddr)
		return
	}

	logger.Info("Query %s[%s] from %s [MISS]",
		dnsq.question[0].Name,
		dnsTypeString(dnsq.question[0].Qtype),
		clientAddr.String())

	//try local look up
	upstreamAddrs := []string{}
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
			logger.Debug(dnsmsg.String())
			self.udpConn.WriteTo(pack, clientAddr)
			self.cache.Insert(q.Name, int(q.Qtype), pack, int(ans[0].Header().Ttl))
			return
		} else {
			// found upstream
			if uaddr, ok := getUpstreamAddr(q.Name); ok {
				upstreamAddrs = append(upstreamAddrs, uaddr)
			}
		}
	}
	upstreamAddrs = append(upstreamAddrs, self.upstreams...)
	for _, usAddr := range upstreamAddrs {
		if replyMsg, err := self.questionUpstream(usAddr, msg); err == nil {
			self.udpConn.WriteTo(replyMsg, clientAddr)
			return
		}
	}

	// Query Failed
	logger.Info("Query %s[%s] from %s [FAIL]",
		dnsq.question[0].Name,
		dnsTypeString(dnsq.question[0].Qtype),
		clientAddr.String())
	dnsmsg.rcode = dnsRcodeServerFailure
	pack, _ := dnsmsg.Pack()
	self.udpConn.WriteTo(pack, clientAddr)
	return

}

func (self *DNSServer) questionUpstream(upstreamAddr string, msg []byte) ([]byte, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", upstreamAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	upConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	qid := []byte{msg[0], msg[1]}

	rid := self.r.Uint16()
	msg[0] = byte(rid >> 8)
	msg[1] = byte(rid)

	upConn.Write(msg)
	upConn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 512)
	n, err := upConn.Read(buf)

	if err != nil {
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			logger.Warning("Upstream %s Timeout", upstreamAddr)
		} else {
			logger.Error("Error Reading from upstream: %s", err.Error())
		}
		return nil, err
	}
	upMsg := buf[:n]

	if len(upMsg) < 12 {
		err = errors.New("Invalid reply message")
		logger.Error(err.Error())
		return nil, err
	}
	if rid != uint16(upMsg[0])<<8+uint16(upMsg[1]) {
		err = errors.New("Invalid return id")
		logger.Error(err.Error())
		return nil, err
	}

	dnsmsg := new(dnsMsg)
	_, err = dnsmsg.Unpack(upMsg, 0)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	if gfwPolluted(dnsmsg) {
		err = fmt.Errorf("GFW polluted %s", dnsmsg)
		logger.Error(err.Error())
		return nil, err
	}

	q := dnsmsg.question[0]
	if len(dnsmsg.answer) > 0 {
		logger.Debug("DNS Reply %s:%d", q.Name, q.Qtype)
		self.cache.Insert(
			q.Name, int(q.Qtype), msg,
			int(dnsmsg.answer[0].Header().Ttl))
	} else {
		logger.Debug(dnsmsg.String())
		self.cache.Insert(
			q.Name, int(q.Qtype), msg, 10)
	}

	upMsg[0] = qid[0]
	upMsg[1] = qid[1]

	return upMsg, nil

}
