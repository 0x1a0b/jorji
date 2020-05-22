package main

import (
)


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

