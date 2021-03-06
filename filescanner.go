package main

import (

  log "github.com/sirupsen/logrus"
  "crypto/x509"
  "crypto/md5"
  "time"
  "io/ioutil"
  "encoding/pem"
  "fmt"

)

const (

  HUMANTIMEFORMAT = "Mon, 02 Jan 2006 15:04:05 -0700"

)

func JorjiScanFile(fileToScan FileScanner) (fileInfos []JorjiFileInfo) {

  pool := CreateCertlistFromFile(fileToScan.Path)
  for _, cert := range pool {
    data, notAfter := CertToCertData(cert)
    fileInfo, _ := CertDataReporting(data, notAfter, fileToScan)
    fileInfos = append(fileInfos, fileInfo)
  }

  return

}


func CreateCertlistFromFile(path string) (certs []x509.Certificate) {

  fileContents, err := ioutil.ReadFile(path)
  if err != nil {
    log.Warnf("failed to read file %v: %v", path, err)
  } else {
    log.Tracef("readfile %v: %v", path, string(fileContents))
  }

  for len(fileContents) > 0 {
    var block *pem.Block
    block, fileContents = pem.Decode(fileContents)
    if block == nil {
      log.Tracef("no more chunks left to parse if %v", path)
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
      log.Tracef("found a remaining certificate chunk in %v", path)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
      log.Tracef("chunk could not be parsed %v", path)
			continue
		}

		certs = append(certs, *cert)
  }

  if (len(certs) > 0) {
    log.Tracef("found %v certificates in %v", len(certs), path)
  } else {
    log.Errorf("no pem x509 certs have been read from %v", path)
  }

  return

}


func CertToCertData(cert x509.Certificate) (data JorjiCertData, NotAfter time.Time) {

  data.Dn = cert.Subject.String()
  data.Cn = cert.Subject.CommonName

  data.IssuerDn = cert.Issuer.String()
  data.IssuerCn = cert.Issuer.CommonName

  data.AllowedDnsNames = cert.DNSNames
  data.AllowedMails = cert.EmailAddresses

  NotAfter = cert.NotAfter
  data.NotAfterUnix = NotAfter.Unix()
  data.NotAfterHuman = NotAfter.Format(HUMANTIMEFORMAT)

  NotBefore := cert.NotBefore
  data.NotBeforeUnix = NotBefore.Unix()
  data.NotBeforeHuman = NotBefore.Format(HUMANTIMEFORMAT)

  Md5Bytes := md5.Sum(cert.Signature)
  data.SignatureMd5 = fmt.Sprintf("%x", Md5Bytes)

  return

}


func CertDataReporting(data JorjiCertData, NotAfter time.Time, fileToScan FileScanner) (fileInfo JorjiFileInfo, mutatedNotAfter time.Time) {

  fileInfo.Certdata = data

  Now := time.Now()

  fileInfo.DaysUntilInvalid = int(NotAfter.Sub(Now).Hours() / 24)
  if (fileToScan.Substractvaliditydays > 0) {
    // fileToScan.Substractvaliditydays should control when we print,
    // but not what we print
    SubtractDays := - fileToScan.Substractvaliditydays
    mutatedNotAfter = NotAfter.AddDate(0, 0, SubtractDays)
  } else {
    mutatedNotAfter = NotAfter
  }

  WarnNow := Now.AddDate(0, 0, Conf.Out.Warnafterdays)
  if (WarnNow.After(mutatedNotAfter)) {
    fileInfo.Level = "WARN"

    log.WithFields(log.Fields{
      "filescannerlog": StructuredFileLog{
        Jorjifileinfo: fileInfo,
        Jorjifilereq: fileToScan,
      },
    }).Warnf("Filescanner threw a warning message for %v", fileToScan.Path)

    if (Conf.Out.Warnexitcodes) {
      if (HighestExitCode < 40) {
        HighestExitCode = 40
        log.Tracef("%v replaces HighestExitCode with 40", fileToScan.Path)
      }
    }

    return

  }

  InfoNow := Now.AddDate(0, 0, Conf.Out.Infoafterdays)
  if (InfoNow.After(mutatedNotAfter)) {
    fileInfo.Level = "INFO"

    log.WithFields(log.Fields{
      "filescannerlog": StructuredFileLog{
        Jorjifileinfo: fileInfo,
        Jorjifilereq: fileToScan,
      },
    }).Infof("Filescanner threw a info message for %v", fileToScan.Path)

    if (Conf.Out.Infoexitcodes) {
      if (HighestExitCode < 30) {
        HighestExitCode = 30
        log.Tracef("%v replaces HighestExitCode with 30", fileToScan.Path)
      }
    }

    return

  }

  DebugNow := Now.AddDate(0, 0, Conf.Out.Debugafterdays)
  if (DebugNow.After(mutatedNotAfter)) {
    fileInfo.Level = "DEBUG"

    log.WithFields(log.Fields{
      "filescannerlog": StructuredFileLog{
        Jorjifileinfo: fileInfo,
        Jorjifilereq: fileToScan,
      },
    }).Debugf("Filescanner threw a debug message for %v", fileToScan.Path)

    if (Conf.Out.Debugexitcodes) {
      if (HighestExitCode < 20) {
        HighestExitCode = 20
        log.Tracef("%v replaces HighestExitCode with 20", fileToScan.Path)
      }
    }

    return

  }

  return

}

