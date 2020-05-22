package main
// structured log object definitions
//
// when a reporter sends logs, he passes along a log object from here. This
// makes post-processing much easier


import (
)


type StructuredFileLog struct {

  // root anchor for message parsing
  Jorjiinfo JorjiFileInfo

  // root anchor for error parsing
  Jorjierror JorjiFileError

}


type JorjiFileError struct {

  // if true, there was a problem reading the file from disk
  FileNotAccessible bool

  // if true, there was a problem parsing the base64 encoded DER file
  FileNotParsable bool

}


type JorjiFileInfo struct {

  // Loglevel, according to the configuration
  // "error" is reserved in case of programatic problems with this file
  Level string

  // Path
  Path string

  // Comment
  Comment string

  // Number of days until expiry
  DaysUntilInvalid int

  // CertData
  Certdata JorjiCertData

}


type JorjiCertData struct {

  // The certificate CN field from the DN
  Cn string

  // The full certificate DN String
  Dn string

  // The issuer CN field from the DN
  IssuerCn string

  // The full issuer DN String
  IssuerDn string

  // List of allowed dns names
  AllowedDnsNames []string

  // List of allowed email addresses
  AllowedMails []string

  // Human readable timestamp when this certificate expires
  // Format: YYYY-MM-DD.HH
  NotAfterHuman string

  // unix timestamp when this certificate expires
  NotAfterUnix int64

  // Human readable timestamp when this certificate begins to be valid
  // Format: YYYY-MM-DD.HH
  NotBeforeHuman string

  // unix timestamp when this certificate begins to be valid
  NotBeforeUnix int64

  // md5 hash of the certificate signature
  // ONLY for deduplication of logmessages
  // don't do anything security related with this field
  SignatureMd5 string

}
