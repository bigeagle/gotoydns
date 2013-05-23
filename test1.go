package main

import (
    "os"
    stdlog "log"
    "github.com/op/go-logging"
    "github.com/bigeagle/gotoydns/dnserver"
)

var port string = ":5053"
var upstream string = "166.111.8.28:53"

var logger = logging.MustGetLogger("toydnsd")

func initLogging() {
    stdoutBackend := logging.NewLogBackend(os.Stdout, "", stdlog.LstdFlags|stdlog.Lshortfile)
    stdoutBackend.Color = true
    logging.SetBackend(stdoutBackend)
    logging.SetLevel(logging.DEBUG, "toydnsd")
}

func checkError(err error) {
    if err != nil {
        logger.Fatal(err.Error())
        os.Exit(1)
    }
}

func main() {
    initLogging()

    var dnserver = toydns.NewServer(port, upstream, logger)
    dnserver.ServeForever()
}
