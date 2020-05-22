package main
// structured log object definitions
//
// when a reporter sends logs, he passes along a log object from here. This
// makes post-processing much easier


import (
)


type StructuredFileLog struct {

  // root anchor for message parsing
  Jorjifileinfo JorjiFileInfo

  // root element for the scanner config
  Jorjifilereq FileScanner

}


type JorjiFileInfo struct {

  // Loglevel, according to the configuration
  // "error" is reserved in case of programatic problems with this file
  Level string

  // Number of days until expiry
  DaysUntilInvalid int

  // CertData
  Certdata JorjiCertData

}

