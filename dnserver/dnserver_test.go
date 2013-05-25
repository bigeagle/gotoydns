package toydns

import (
    "fmt"
    "strings"
    "testing"
)

func Test_rr_new(t *testing.T) {
    rr, err := newRR("test.example.com", dnsTypeA, 600, "192.168.0.1")
    if err != nil {
        t.Error("A record failed with error:", err)
    }
    fmt.Println(rr.String())

    rr, err = newRR("test.example.com", dnsTypeCNAME, 600, "example.com")
    if err != nil {
        t.Error("CNAME record failed with error:", err)
    }
    fmt.Println(rr.String())

    rr, err = newRR("test.example.com", dnsTypeAAAA, 600, "2001:470:20::2")
    if err != nil {
        t.Error("AAAA record failed with error:", err)
    }
    fmt.Println(rr.String())

}


func Test_rr_read(t *testing.T) {
    recordString := "thunics.org. # domain\n" +
        "@       A       600  10.137.1.1\n" +
        "db3     CNAME   600  srv3.thunics.org\n" +
        "srv3    A       600  10.137.2.3"


    db, err := readRecords(strings.NewReader(recordString))


    for k, domain := range db.domains {
        fmt.Println(k)
        for r, rr := range domain.records {
            fmt.Printf("%s: %s\n", r, rr.String())
        }
    }

    fmt.Println(matchQuery("db3.thunics.org.", db))
    fmt.Println(matchQuery("thunics.org.", db))

    if err != nil {
        t.Error("error reading record file:", err)
    }

    ans := make([]dnsRR, 0, 10)
    queryDB("db3.thunics.org.", dnsTypeA, db, &ans)
    //fmt.Println(n, len(ans))
    for _, rr := range ans {
        //fmt.Println(i)
        fmt.Println(rr.String())
    }

}

