package toydns

import (
    "bufio"
    "errors"
    "fmt"
    "io"
    "os"
    "regexp"
    "strconv"
    "strings"
)

type domain struct {
    name    string
    records map[string]dnsRR
}

type domainDB struct {
    regexs  map[string]*regexp.Regexp //match patterns
    domains map[string]*domain
}

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
            var name string
            var rrtype int
            record, srtype, sttl, rdata := tokens[0], tokens[1], tokens[2], tokens[3]
            if record == "@" {
                name = ""
            } else {
                name = record + "."
            }
            name += curDomain

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
            if err != nil {
                return nil, err
            }

            rkey := record + ":" + strconv.Itoa(rrtype)
            db.domains[curDomain].records[rkey] = rr

        default:
            continue
        }
    }

    return db, nil
}

func matchQuery(qname string, db *domainDB) (dkey string, record string, match bool) {

    for dkey, drgx := range db.regexs {
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
            return "", "", false
        }
    }

    return "", "", false
}

func queryDB(qname string, qtype int, db *domainDB, ans *[]dnsRR) (found bool) {
    //non-recursive query
    nrquery := func(dkey string, record string, qtype int) (rr dnsRR, found bool) {
        rkey := rkeyGen(record, qtype)
        rr, found = db.domains[dkey].records[rkey]
        return rr, found
    }

    dkey, record, match := matchQuery(qname, db)
    if !match {
        return false
    }

    rr, found := nrquery(dkey, record, qtype)
    if found {
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
