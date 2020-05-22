package main

import (

  "github.com/sherifabdlnaby/configuro"
  log "github.com/sirupsen/logrus"
  "github.com/davecgh/go-spew/spew"
  splunk "github.com/Franco-Poveda/logrus-splunk-hook"
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

  if (Conf.Hec.Enabled==true) {
    splunkClient := splunk.Client{
      URL: Conf.Hec.Url,
      Hostname: Conf.Hec.Hostname,
      Token: Conf.Hec.Secret,
      Source: Conf.Hec.Source,
      SourceType: Conf.Hec.Sourcetype,
      Index: Conf.Hec.Index,
    }
    log.AddHook(splunk.NewHook(&splunkClient, []log.Level{
      log.PanicLevel,
      log.FatalLevel,
      log.ErrorLevel,
      log.WarnLevel,
      log.InfoLevel,
      log.DebugLevel,
    }))
  }

}

func main() () {

  StartFromCmd()

}

func StartFromCmd() () {

  if (len(os.Args) == 2) {
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
    log.Tracef("Exiting with code %v", HighestExitCode)
    os.Exit(HighestExitCode)
  } else {
    ShowUsage()
  }

}

func RunAllJorjiScanners() () {

  for _, fileScan := range Conf.Scanfiles {
    JorjiScanFile(fileScan)
  }

  for _, tlsExpiryScanner := range Conf.Scantlsexpiry {
    JorjiScanTlsExpiry(tlsExpiryScanner)
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
