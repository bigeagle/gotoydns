package toydns

import (
    "strconv"
    "sync"
    "time"
)

type cacheItem struct {
    ts   int64
    ttl  int
    pack []byte
}

type dnsCache struct {
    cache map[string]*cacheItem
}

var _lock sync.RWMutex

func newDNSCache() *dnsCache {
    dnscache := new(dnsCache)
    dnscache.cache = make(map[string]*cacheItem, 0)
    return dnscache
}

func (self *dnsCache) Get(qname string, qtype int) ([]byte, bool) {
    key := qname + ":" + strconv.Itoa(qtype)
    _lock.RLock()
    item, found := self.cache[key]
    _lock.RUnlock()
    if !found {
        return nil, false
    } else {
        nowts := time.Now().Unix()
        if nowts-item.ts >= int64(item.ttl) {
            _lock.Lock()
            delete(self.cache, key)
            _lock.Unlock()
            log.Debug("Ttl expired")
            return nil, false
        }
        return item.pack, true
    }
}

func (self *dnsCache) Insert(qname string, qtype int, pack []byte, ttl int) error {
    key := qname + ":" + strconv.Itoa(qtype)
    _lock.RLock()
    _, found := self.cache[key]
    _lock.RUnlock()
    if found {
        return nil
    } else {
        nowts := time.Now().Unix()
        citem := &cacheItem{ts: nowts, ttl: ttl, pack: pack}
        _lock.Lock()
        self.cache[key] = citem
        _lock.Unlock()
        return nil
    }
}
