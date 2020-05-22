package main


import (

  log "github.com/sirupsen/logrus"
  "crypto/x509"
  "crypto/tls"
  "time"

)


func JorjiScanTlsExpiry(tlsExpiryScanner TlsExpiryScanner) (tlsExpiryInfos []JorjiTlsExpiryInfo) {

  rcvdCerts := GetCertFromWire(tlsExpiryScanner)

  for _, cert := range rcvdCerts {
    data, notAfter := CertToCertData(cert)
    tlsInfo, _ := TlsCertReporting(data, notAfter, tlsExpiryScanner)
    tlsExpiryInfos = append(tlsExpiryInfos, tlsInfo)
  }

  return

}


func GetCertFromWire(tlsExpiryScanner TlsExpiryScanner) (remoteCerts []x509.Certificate) {

  var conf tls.Config

  if (tlsExpiryScanner.Sniindicator=="") {
    conf = tls.Config{
      InsecureSkipVerify: true,
      MinVersion: tls.VersionTLS10,
      MaxVersion: tls.VersionTLS13,
    }
  } else {
    conf = tls.Config{
      InsecureSkipVerify: true,
      MinVersion: tls.VersionTLS10,
      MaxVersion: tls.VersionTLS13,
      ServerName: tlsExpiryScanner.Sniindicator,
    }
  }

  conn, err := tls.Dial("tcp", tlsExpiryScanner.Connect, &conf)

	if err != nil {
		log.Errorf("failed to dial: " + err.Error())
    return
	}
  defer conn.Close()

  state := conn.ConnectionState()

  for _, remoteCert := range state.PeerCertificates {
    remoteCerts = append(remoteCerts, *remoteCert)
  }

  return

}

func TlsCertReporting(data JorjiCertData, NotAfter time.Time, tlsExpiryScanner TlsExpiryScanner) (tlsExpiryInfo JorjiTlsExpiryInfo, mutatedNotAfter time.Time) {

  tlsExpiryInfo.Certdata = data

  Now := time.Now()

  tlsExpiryInfo.DaysUntilInvalid = int(NotAfter.Sub(Now).Hours() / 24)
  if (tlsExpiryScanner.Substractvaliditydays > 0) {
    // fileToScan.Substractvaliditydays should control when we print,
    // but not what we print
    SubtractDays := - tlsExpiryScanner.Substractvaliditydays
    mutatedNotAfter = NotAfter.AddDate(0, 0, SubtractDays)
  } else {
    mutatedNotAfter = NotAfter
  }

  WarnNow := Now.AddDate(0, 0, Conf.Out.Warnafterdays)
  if (WarnNow.After(mutatedNotAfter)) {
    tlsExpiryInfo.Level = "WARN"

    log.WithFields(log.Fields{
      "tlsexpiryscannerlog": StructuredTlsExpiryLog{
        Jorjitlsexpinfo: tlsExpiryInfo,
        Jorjitlsexpreq: tlsExpiryScanner,
      },
    }).Warnf("Filescanner threw a warning message for %v(%v)", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)

    if (Conf.Out.Warnexitcodes) {
      if (HighestExitCode < 40) {
        HighestExitCode = 40
        log.Tracef("%v(%v) replaces HighestExitCode with 40", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)
      }
    }

    return

  }

  InfoNow := Now.AddDate(0, 0, Conf.Out.Infoafterdays)
  if (InfoNow.After(mutatedNotAfter)) {
    tlsExpiryInfo.Level = "INFO"

    log.WithFields(log.Fields{
      "tlsexpiryscannerlog": StructuredTlsExpiryLog{
        Jorjitlsexpinfo: tlsExpiryInfo,
        Jorjitlsexpreq: tlsExpiryScanner,
      },
    }).Infof("Filescanner threw a info message for %v(%v)", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)

    if (Conf.Out.Infoexitcodes) {
      if (HighestExitCode < 30) {
        HighestExitCode = 30
        log.Tracef("%v(%v) replaces HighestExitCode with 30", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)
      }
    }

    return

  }

  DebugNow := Now.AddDate(0, 0, Conf.Out.Debugafterdays)
  if (DebugNow.After(mutatedNotAfter)) {
    tlsExpiryInfo.Level = "DEBUG"

    log.WithFields(log.Fields{
      "tlsexpiryscannerlog": StructuredTlsExpiryLog{
        Jorjitlsexpinfo: tlsExpiryInfo,
        Jorjitlsexpreq: tlsExpiryScanner,
      },
    }).Debugf("Filescanner threw a debug message for %v(%v)", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)

    if (Conf.Out.Debugexitcodes) {
      if (HighestExitCode < 20) {
        HighestExitCode = 20
        log.Tracef("%v(%v) replaces HighestExitCode with 20", tlsExpiryScanner.Connect, tlsExpiryScanner.Sniindicator)
      }
    }

    return

  }

  return

}
