package main

import (

  "testing"
	"crypto/ecdsa"
  "crypto/rsa"
	"crypto/elliptic"
	"crypto/rand"
  "crypto/x509"
  "crypto/x509/pkix"
  "time"
  log "github.com/sirupsen/logrus"
  "math/big"
  "bytes"
  "encoding/pem"
  "io/ioutil"
  "os"
  "github.com/davecgh/go-spew/spew"

)

func TestFilescanner_JorjiScanFile(t *testing.T) {
  suite := []TestFilescanner_JorjiScanFile_TestCase{
    TestFilescanner_JorjiScanFile_TestCase{
      Testname: "far into the future should be a debug case",
      Filepath: "./testfile_farintofuture",
      ValidDays: 1000,
      Substractvaliditydays: 0,
      Warnafterdays: 100,
      ExpectWarn: false,
      Infoafterdays: 200,
      ExpectInfo: false,
      Debugafterdays: 2000,
      ExpectDebug: true,
    },
    TestFilescanner_JorjiScanFile_TestCase{
      Testname: "next quater of a year should be info",
      Filepath: "./testfile_thisquater",
      ValidDays: 80,
      Substractvaliditydays: 2,
      Warnafterdays: 30,
      ExpectWarn: false,
      Infoafterdays: 90,
      ExpectInfo: true,
      Debugafterdays: 200,
      ExpectDebug: false,
    },
    TestFilescanner_JorjiScanFile_TestCase{
      Testname: "this month should raise warn",
      Filepath: "./testfile_thismonth",
      ValidDays: 25,
      Substractvaliditydays: 0,
      Warnafterdays: 30,
      ExpectWarn: true,
      Infoafterdays: 60,
      ExpectInfo: false,
      Debugafterdays: 90,
      ExpectDebug: false,
    },
    TestFilescanner_JorjiScanFile_TestCase{
      Testname: "Substractvaliditydays edge case",
      Filepath: "./testfile_subdays_edge",
      ValidDays: 30,
      Substractvaliditydays: 1,
      Warnafterdays: 30,
      ExpectWarn: true,
      Infoafterdays: 31,
      ExpectInfo: false,
      Debugafterdays: 32,
      ExpectDebug: false,
    },
  }

  for _, test := range suite {

     helperTestFilescanner_JorjiScanFile_SetupSzenario(test)
     defer helperTestFilescanner_JorjiScanFile_CleanupSzenario(test)

     Conf.Out.Warnafterdays = test.Warnafterdays
     Conf.Out.Infoafterdays = test.Infoafterdays
     Conf.Out.Debugafterdays = test.Debugafterdays

     scannerReq := FileScanner{
       Path: test.Filepath,
       Substractvaliditydays: test.Substractvaliditydays,
       Comment: test.Testname,
     }

     scannerResults := JorjiScanFile(scannerReq)

     if (test.ExpectWarn==true) {
       if !(scannerResults[0].Level=="WARN") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-negative for WARN")
       }
     } else {
       if (scannerResults[0].Level=="WARN") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-positive for WARN")
       }
     }

     if (test.ExpectInfo==true) {
       if !(scannerResults[0].Level=="INFO") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-negative for INFO")
       }
     } else {
       if (scannerResults[0].Level=="INFO") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-positive for INFO")
       }
     }

     if (test.ExpectDebug==true) {
       if !(scannerResults[0].Level=="DEBUG") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-negative for DEBUG")
       }
     } else {
       if (scannerResults[0].Level=="DEBUG") {
         spew.Dump(test)
         spew.Dump(Conf)
         spew.Dump(scannerResults)
         t.Error("incorrect result, false-positive for DEBUG")
       }
     }

  }

}

func helperTestFilescanner_JorjiScanFile_SetupSzenario(test TestFilescanner_JorjiScanFile_TestCase) () {
  _ = helperTest_Filescanner_JorjiScanFile_CreateCertfile(test.Filepath, test.ValidDays)
}

func helperTestFilescanner_JorjiScanFile_CleanupSzenario(test TestFilescanner_JorjiScanFile_TestCase) () {
  err := os.Remove(test.Filepath)
  if err != nil {
    log.Fatal(err)
  }
}

type TestFilescanner_JorjiScanFile_TestCase struct {
  Testname string
  Filepath string
  ValidDays int
  Substractvaliditydays int
  Warnafterdays int
  Infoafterdays int
  Debugafterdays int
  ExpectWarn bool
  ExpectInfo bool
  ExpectDebug bool
}

func helperTest_Filescanner_JorjiScanFile_CreateCertfile(path string, validForDays int) (err error) {

  priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
  if err != nil {
    log.Fatal(err)
  }
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ACME Go"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, validForDays),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, helperTest_Filescanner_JorjiScanFile_PublicKey(priv), priv)
  if err != nil {
    log.Fatal(err)
  }
  out := &bytes.Buffer{}
  pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  bytes, _ := ioutil.ReadAll(out)
  err = ioutil.WriteFile(path, bytes, 0644)
  if err != nil {
    log.Fatal(err)
  }

  return

}

func helperTest_Filescanner_JorjiScanFile_PublicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
