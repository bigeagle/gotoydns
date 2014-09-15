package toydns

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
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
	cfg       *srvConfig
	conn      dnsConn
	r         *random
	rdb       *domainDB
	cache     *dnsCache
	upstreams []*upstreamEntry
}

func NewServer(configFile string, _log _Logger) (*DNSServer, error) {
	dns := &DNSServer{}
	if _log == nil {
		return nil, errors.New("No logger specified")
	}
	logger = _log
	if err := dns.initServer(configFile); err != nil {
		return nil, err
	}
	return dns, nil
}

func (self *DNSServer) initServer(configFile string) error {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	self.cfg = cfg

	self.conn, err = listenDNS(cfg.Listen)
	if err != nil {
		return err
	}

	logger.Info("Start Listening on %v", self.conn)

	self.rdb = nil
	if cfg.RecordFile != "" {

		fatal := func(err error) {
			logger.Fatal(err)
		}

		readDB := func() {
			db, err := readRecordsFile(cfg.RecordFile)
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

		err = watcher.Watch(cfg.RecordFile)
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

	self.upstreams = make([]*upstreamEntry, 0, 4)
	for _, e := range cfg.Upstreams {
		upstream := newUpstreamEntry(e)
		self.upstreams = append(self.upstreams, upstream)
	}

	return nil
}

func (self *DNSServer) ServeForever() error {

	for {
		msg, clientAddr, err := self.conn.ReadPacketFrom()
		if err != nil {
			continue
		}
		go self.handleClient(msg, clientAddr)
	}

	return errors.New("Here should not be reached")
}

func (self *DNSServer) handleClient(dnsq *dnsMsg, clientAddr net.Addr) {
	qid := dnsq.id

	//try cache
	cpack, found := self.cache.Get(dnsq.question[0].Name, int(dnsq.question[0].Qtype))
	if found {
		cpack[0] = byte(qid >> 8)
		cpack[1] = byte(qid)
		logger.Info("Query %s[%s] from %s [HIT]",
			dnsq.question[0].Name,
			dnsTypeString(dnsq.question[0].Qtype),
			clientAddr.String(),
		)
		self.conn.WriteTo(cpack, clientAddr)
		return
	}

	logger.Info("Query %s[%s] from %s [MISS]",
		dnsq.question[0].Name,
		dnsTypeString(dnsq.question[0].Qtype),
		clientAddr.String())

	//try local look up
	upstreamEntries := []*upstreamEntry{}
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
			self.conn.WriteTo(pack, clientAddr)
			self.cache.Insert(q.Name, int(q.Qtype), pack, int(ans[0].Header().Ttl))
			return
		}

		// found upstream
		if uaddr, ok := getUpstreamAddr(q.Name); ok {
			upstreamEntries = append(upstreamEntries, newUpstreamEntry(uaddr))
		}
	}

	upstreamEntries = append(upstreamEntries, self.upstreams...)
	for _, upstream := range upstreamEntries {
		if replyMsg, err := self.questionUpstream(upstream, *dnsq); err == nil {
			self.conn.WriteTo(replyMsg, clientAddr)
			return
		} else {
			logger.Error(upstream.udpAddr + err.Error())
		}
	}

	// Query Failed
	logger.Info("Query %s[%s] from %s [FAIL]",
		dnsq.question[0].Name,
		dnsTypeString(dnsq.question[0].Qtype),
		clientAddr.String())
	dnsmsg.rcode = dnsRcodeServerFailure
	self.conn.WritePacketTo(dnsmsg, clientAddr)
	return

}

func (self *DNSServer) questionUpstream(entry *upstreamEntry, dnsq dnsMsg) ([]byte, error) {
	conn, err := dialUpstream(entry)
	if err != nil {
		return nil, err
	}
	// logger.Debug("%s", dnsq)
	qid := dnsq.id
	msg, _ := dnsq.Pack()

	for i := 0; i < self.cfg.Repeat; i++ {
		conn.Write(msg)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	upMsg, err := conn.Read()

	if err != nil {
		if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
			logger.Warning("Upstream %v Timeout", conn)
		} else {
			logger.Error("Error Reading from upstream: %s", err.Error())
		}
		return nil, err
	}

	if len(upMsg) < 12 {
		err = errors.New("Invalid reply message")
		logger.Error(err.Error())
		return nil, err
	}

	if qid != uint16(upMsg[0])<<8+uint16(upMsg[1]) {
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

	if len(dnsmsg.question) == 0 {
		return nil, errors.New("Invalid Question")
	}

	q := dnsmsg.question[0]
	if len(dnsmsg.answer) > 0 {
		logger.Debug("DNS Reply %s:%d", q.Name, q.Qtype)
		self.cache.Insert(
			q.Name, int(q.Qtype), upMsg,
			int(dnsmsg.answer[0].Header().Ttl))
	} else {
		logger.Debug(dnsmsg.String())
		self.cache.Insert(
			q.Name, int(q.Qtype), upMsg, 3)
	}

	return upMsg, nil

}
