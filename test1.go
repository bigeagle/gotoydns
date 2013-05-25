package main

import (
    "os"
    stdlog "log"
    "flag"
    "strings"
    "github.com/op/go-logging"
    "github.com/bigeagle/gotoydns/dnserver"
)

var port string
var upstream string
var recordfile string
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
    flag.StringVar(&port, "p", "53", "DNS Server port")
    flag.StringVar(&upstream, "u", "166.111.8.28:53", "Upstream server addr:port")
    flag.StringVar(&recordfile, "r", "", "Record file")
    flag.BoolVar(&debugMode, "debug", false, "Debug")

    flag.Parse()

    if !strings.HasPrefix(port, ":") {
        port = ":" + port
    }

    initLogging()

    //logger.Debug(port)


    dnserver, err := toydns.NewServer(port, upstream, recordfile, logger)
    if err != nil {
        logger.Fatal("Failed to init DNS server: ", err)
    }

    dnserver.ServeForever()
}
