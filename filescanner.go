package main

import (
  log "github.com/sirupsen/logrus"
)

func JorjiScanFile(fileToScan FileScanner) () {
  log.Warnf("Hello from scanner %v", fileToScan.Path)
}
