package toydns

import (
	"fmt"
	"strings"
	"testing"
)

func Test_Suffix_Tree(t *testing.T) {
	root := newSuffixTree("", nil)
	root.insert("cn", "114.114.114.114")
	root.sinsert([]string{"baidu", "cn"}, "166.111.8.28")
	root.sinsert([]string{"sina", "cn"}, "114.114.114.114")

	root.sinsert(strings.Split("com", "."), nil)
	root.sinsert(strings.Split("google.com", "."), "8.8.8.8")
	root.sinsert(strings.Split("twitter.com", "."), "8.8.8.8")
	root.sinsert(strings.Split("scholar.google.com", "."), "208.67.222.222")

	v, found := root.search(strings.Split("google.com", "."))
	fmt.Println(v, found)

	v, found = root.search(strings.Split("scholar.google.com", "."))
	fmt.Println(v, found)

	v, found = root.search(strings.Split("baidu.com", "."))
	fmt.Println(v, found)

	v, found = root.search(strings.Split("baidu.cn", "."))
	fmt.Println(v, found)

	v, found = root.search(strings.Split("www.tsinghua.edu.cn", "."))
	fmt.Println(v, found)
}
