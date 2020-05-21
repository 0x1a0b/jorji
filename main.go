package main

import (

  "github.com/sherifabdlnaby/configuro"
  log "github.com/sirupsen/logrus"
  "github.com/davecgh/go-spew/spew"
  "os"
  "time"
  "fmt"

)

var (

  Conf Config
  HighestExitCode int

)

func init() () {

  log.SetFormatter(&log.JSONFormatter{})
  log.SetReportCaller(true)

  loader, err := configuro.NewConfig()
  if err != nil {
    log.Fatalf("Error creating config loader: %v", err)
  }

  err = loader.Load(&Conf)
  if err != nil {
    log.Fatalf("Error loading configuration: %v", err)
  }

  if (Conf.Debug == true) {
    log.SetLevel(log.TraceLevel)
    spew.Dump(Conf)
  } else {
    log.SetLevel(log.DebugLevel)
  }

}

func main() () {

  StartFromCmd()

}

func StartFromCmd() () {

  if (os.Args[1] == "exec") {
    RunAllJorjiScanners()
  } else if (os.Args[1] == "server") {
    for {
      RunAllJorjiScanners()
      time.Sleep(time.Duration(Conf.Serverintervalminutes) * time.Minute)
    }
  } else {
    ShowUsage()
  }
  os.Exit(HighestExitCode)

}

func RunAllJorjiScanners() () {

  for _, fileScan := range Conf.Scanfiles {
    JorjiScanFile(fileScan)
  }

}

func ShowUsage() () {

  usage := `
  Jorji Version 0.0.1 Usage

  jorji server - run scans continously
  jorji exec   - run a single scan
  
  `
  fmt.Fprintln(os.Stderr, usage)

}
