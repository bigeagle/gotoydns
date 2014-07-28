package main

import (
	"flag"
	stdlog "log"
	"os"

	"github.com/bigeagle/go-logging"
	"github.com/bigeagle/gotoydns/dnserver"
)

var configFile string
var debugMode bool
var logger = logging.MustGetLogger("toydnsd")

func initLogging() {

	stdoutBackend := logging.NewLogBackend(os.Stdout, "", stdlog.LstdFlags|stdlog.Lshortfile)
	logging.SetBackend(stdoutBackend)

	if debugMode {
		stdoutBackend.Color = true
		logging.SetLevel(logging.DEBUG, "toydnsd")
	} else {
		logging.SetLevel(logging.INFO, "toydnsd")
	}

}

func checkError(err error) {
	if err != nil {
		logger.Fatal(err.Error())
		os.Exit(1)
	}
}

func main() {
	flag.StringVar(&configFile, "c", "/etc/godnsd.conf", "Config File")
	flag.BoolVar(&debugMode, "debug", false, "Debug")
	flag.Parse()

	initLogging()

	//logger.Debug(port)
	logger.Debug(configFile)
	dnserver, err := toydns.NewServer(configFile, logger)

	if err != nil {
		logger.Fatal("Failed to init DNS server: ", err)
	}

	dnserver.ServeForever()
}
