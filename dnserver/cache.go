package toydns

import (
    "time"
    "strconv"
)

type cacheItem struct {
    ts int64
    ttl int
    pack []byte
}

type dnsCache struct {
    cache map[string] *cacheItem
}

func newDNSCache() *dnsCache {
    dnscache := new(dnsCache)
    dnscache.cache = make(map[string] *cacheItem, 0)
    return dnscache
}

func (self *dnsCache) Get(qname string, qtype int) ([]byte, bool) {
    key := qname + ":" + strconv.Itoa(qtype)
    item, found := self.cache[key]
    if ! found {
        return nil, false
    } else {
        nowts := time.Now().Unix()
        if nowts - item.ts >= int64(item.ttl) {
            delete(self.cache, key)
            if log != nil {
                log.Debug("Ttl expired")
            }
            return nil, false
        }
        return item.pack, true
    }
}

func (self *dnsCache) Insert(qname string, qtype int, pack []byte, ttl int) error {
    key := qname + ":" + strconv.Itoa(qtype)
    _, found := self.cache[key]
    if found {
        return nil
    } else {
        nowts := time.Now().Unix()
        citem := &cacheItem{ts: nowts, ttl: ttl, pack: pack}
        self.cache[key] = citem
        return nil
    }
}

