package toydns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// a domain and records
type domain struct {
	name    string
	records map[string]dnsRR
}

// manage domains
type domainDB struct {
	regexs  map[string]*regexp.Regexp //match patterns
	domains map[string]*domain
}

// upstreams for specified domain
var upstreamTree *suffixTreeNode

// generate record key
func rkeyGen(record string, rtype int) string {
	return record + ":" + strconv.Itoa(rtype)
}

func readRecordsFile(path string) (*domainDB, error) {
	file, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	return readRecords(file)
}

func readRecords(rd io.Reader) (*domainDB, error) {
	db := new(domainDB)
	db.regexs = make(map[string]*regexp.Regexp, 1)
	db.domains = make(map[string]*domain, 1)
	var curDomain string

	br := bufio.NewReader(rd)
	upstreamTree = newSuffixTree("", nil)

	for {
		line, isPrefix, err1 := br.ReadLine()

		if err1 != nil {
			if err1 != io.EOF {
				return nil, err1
			}
			break
		}

		if isPrefix {
			return nil, errors.New("Line too long")
		}

		str_line := string(line)

		strs := strings.Split(str_line, "#")[0]

		if len(strs) == 0 {
			continue
		}

		tokens := make([]string, 0)
		for _, t := range strings.Split(strs, " ") {
			t = strings.TrimSpace(t)
			if len(t) == 0 {
				continue
			}
			//fmt.Println(t, []byte(t), len(t))
			tokens = append(tokens, t)
		}

		//fmt.Println(tokens, len(tokens))

		switch len(tokens) {

		// len 1 is domain name
		case 1:
			//logger.Debug("1: %v", tokens)
			curDomain = tokens[0]

			rdomain := strings.Replace(curDomain, `.`, `\.`, -1)
			rx, err := regexp.Compile(`^([-A-Za-z0-9.]*)\.?` + rdomain + `$`)

			if err != nil {
				return nil, err
			}
			db.regexs[curDomain] = rx
			domain := &domain{name: curDomain, records: make(map[string]dnsRR, 4)}
			db.domains[curDomain] = domain

		// len 4 is record
		case 4:
			//logger.Debug("4: %v", tokens)
			var name string
			var rrtype int
			record, srtype, sttl, rdata := tokens[0], tokens[1], tokens[2], tokens[3]
			var wildcard = false

			switch record {
			case "@":
				name = ""
			case "*":
				wildcard = true
			default:
				name = record + "."
			}

			if wildcard {
				name = ""
			} else {
				name += curDomain
			}

			switch srtype {
			case "A":
				rrtype = dnsTypeA
			case "AAAA":
				rrtype = dnsTypeAAAA
			case "CNAME":
				rrtype = dnsTypeCNAME
				if !strings.HasSuffix(rdata, ".") {
					rdata += "."
				}
			default:
				return nil, fmt.Errorf("unsported record type: %s", srtype)
			}

			ttl, err := strconv.Atoi(sttl)
			if err != nil {
				return nil, err
			}

			rr, err := newRR(name, rrtype, ttl, rdata)
			//logger.Debug("%s %v", name, rr.Header().Rdlength)
			if err != nil {
				return nil, err
			}

			rkey := record + ":" + strconv.Itoa(rrtype)
			db.domains[curDomain].records[rkey] = rr

		case 2:
			// upstream
			//logger.Debug("2: %v", tokens)
			domain, upaddr := tokens[0], tokens[1]

			if _, err := net.ResolveUDPAddr("udp", upaddr); err == nil {
				upaddr = upaddr
			} else if _ip := net.ParseIP(upaddr); _ip != nil {
				upaddr = upaddr + ":53"
			} else {
				continue
			}

			upstreamTree.sinsert(strings.Split(domain, "."), upaddr)

		default:
			logger.Debug("none: %v", tokens)
			continue
		}
	}

	return db, nil
}

func matchQuery(qname string, db *domainDB) (dkey string, record string, match bool) {

	for dkey, drgx := range db.regexs {

		//logger.Debug(dkey)
		matches := drgx.FindStringSubmatch(qname)
		switch len(matches) {
		case 2:
			record := matches[1]
			if len(record) == 0 {
				record = "@"
			} else {
				record = record[:len(record)-1]
			}
			return dkey, record, true
		default:
			continue
		}
	}

	return "", "", false
}

func queryDB(qname string, qtype int, db *domainDB, ans *[]dnsRR) (found bool) {
	//non-recursive query
	nrquery := func(dkey string, record string, qtype int) (rr dnsRR, found bool) {
		rkey := rkeyGen(record, qtype)
		rr, found = db.domains[dkey].records[rkey]
		if !found {
			rkey := rkeyGen("*", qtype)
			rr, found = db.domains[dkey].records[rkey]
		}
		return rr, found
	}

	dkey, record, match := matchQuery(qname, db)
	if !match {
		return false
	}

	rr, found := nrquery(dkey, record, qtype)

	if found {
		if rr.Header().Name == "" {
			rr.Header().Name = qname
		}
		*ans = append(*ans, rr)
	} else {
		//if CNAME is avalible
		_rr, _found := nrquery(dkey, record, dnsTypeCNAME)
		if _found {
			*ans = append(*ans, _rr)

			cname := _rr.Rdata().(string)
			if !strings.HasSuffix(cname, ".") {
				cname += "."
			}
			return queryDB(cname, qtype, db, ans)
		}
		return false
	}
	return true
}

func getUpstreamAddr(qname string) (string, bool) {
	queryKeys := strings.Split(qname, ".")
	queryKeys = queryKeys[:len(queryKeys)-1] // ignore last '.'

	if v, found := upstreamTree.search(queryKeys); found {
		logger.Debug("found upstream: %v", v)
		return v.(string), true
	}
	return "", false
}
