package main

import (
)

type StructuredTlsExpiryLog struct {

  // root anchor for message parsing
  Jorjitlsexpinfo JorjiTlsExpiryInfo

  ´// root element of the scanner configuration
  Jorjitlsexpreq TlsExpiryScanner

}

type JorjiTlsExpiryInfo struct {

  // Loglevel, according to the configuration
  // "error" is reserved in case of programatic problems with this file
  Level string

  // Number of days until expiry
  DaysUntilInvalid int

  // CertData
  Certdata JorjiCertData

}

