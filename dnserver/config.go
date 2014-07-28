package toydns

import (
	"io/ioutil"

	"gopkg.in/yaml.v1"
)

const (
	PROTO_UDP   = "UDP"
	PROTO_DNS   = "DNS"
	PROTO_CRYPT = "CRYPT"
)

type srvEntry struct {
	Protocol string `yaml:"protocol"`
	Addr     string `yaml:"addr"`
	Port     int    `yaml:"port"`
	Key      string `yaml:"key"`
}

type srvConfig struct {
	Listen srvEntry `yaml:"listen"`

	RecordFile string     `yaml:"record_file"`
	Upstreams  []srvEntry `yaml:"upstreams"`
	Repeat     int        `yaml:"repeat"`
	FuckGFW    bool       `yaml:"fuck_gfw"`
}

func loadConfig(cfgFile string) (*srvConfig, error) {
	cfg := srvConfig{
		Listen: srvEntry{
			Protocol: "DNS",
			Addr:     "127.0.0.1",
			Port:     53,
		},
		RecordFile: "",
		Repeat:     1,
		FuckGFW:    false,
	}

	if cfgFile != "" {
		content, err := ioutil.ReadFile(cfgFile)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}

		err = yaml.Unmarshal(content, &cfg)
		if err != nil {
			logger.Error(err.Error())
			return nil, err
		}

	}
	logger.Debug("%v", cfg)
	return &cfg, nil

}
