package main


import (
  "crypto/x509"
  "crypto/tls"

)


func JorjiScanTlsExpiry(tlsExpiryScanner TlsExpiryScanner) (tlsExpiryInfos []JorjiTlsExpiryInfo) {

  rcvdCerts := GetCertFromWire(tlsExpiryScanner)

  for _, cert := range rcvdCerts {
    data, notAfter := CertToCertData(cert)
    tlsInfo, _ := TlsCertReporting(data, notAfter, tlsExpiryScanner)
    tlsExpiryInfos = append(tlsExpiryInfos, tlsInfo)
  }

}


func GetCertFromWire(tlsExpiryScanner TlsExpiryScanner) (remoteCerts []x509.Certificate) {
  var certs []tls.Certificate
  if (tlsExpiryScanner.Tlsclientpem != "") {
    cert, err := tls.LoadX509KeyPair(tlsExpiryScanner.Tlsclientpem, tlsExpiryScanner.Tlsclientpem)
    if err != nil {
      log.Fatalf("failed to load configured client cert %", tlsExpiryScanner)
    }
    certs = append(certs, cert)
  }
  conn, err := tls.Dial("tcp", tlsExpiryScanner.Connect, &tls.Config{
    InsecureSkipVerify: true,
    CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
    PreferServerCipherSuites: false,
    CipherSuites: []uint16{
      tls.TLS_RSA_WITH_RC4_128_SHA
      tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
      tls.TLS_RSA_WITH_AES_128_CBC_SHA
      tls.TLS_RSA_WITH_AES_256_CBC_SHA
      tls.TLS_RSA_WITH_AES_128_CBC_SHA256
      tls.TLS_RSA_WITH_AES_128_GCM_SHA256
      tls.TLS_RSA_WITH_AES_256_GCM_SHA384
      tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
      tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA
      tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
      tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
      tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
      tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
      tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
      tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
      tls.TLS_AES_128_GCM_SHA256
      tls.TLS_AES_256_GCM_SHA384
      tls.TLS_CHACHA20_POLY1305_SHA256
    },
    MinVersion: tls.VersionTLS10,
    MaxVersion: tls.VersionTLS13,
    ServerName: tlsExpiryScanner.Sniindicator,
    Certificates: certs,
	})
	if err != nil {
		panic("failed to connect: " + err.Error())
	}
  state := conn.ConnectionState()
  //ocsp := conn.OCSPResponse()
	conn.Close()
  for _, remoteCert := range state.PeerCertificates {
    remoteCerts = append(remoteCerts, *remoteCert)
  }
}

func TlsCertReporting(data JorjiCertData, NotAfter time.Time, tlsExpiryScanner TlsExpiryScanner) (tlsExpiryInfo JorjiTlsExpiryInfo, mutatedNotAfter time.Time) {
}
