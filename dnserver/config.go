package toydns

import (
	"flag"
	"strings"
	"github.com/BurntSushi/toml"
)

type upstreamEntry struct {
	protocol string `toml:"protocol"`
	addr string `toml:"addr"`
	port int `toml:"port"`
}

type srvConfig struct {
	listen string `toml:"listen"`
	recordFile string `toml:"record_file"`
	fuckGFW bool `toml:"fuck_gfw"`
	upstreams []upstreamEntry `toml:"upstreams"`
}
