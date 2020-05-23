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
  "sync"
  "net/http"
  "crypto/tls"


)


type TestExpiryScanner_JorjiScanTlsExpiry_Testcase struct {

  Name string

  Bind string
  Sni string
  ValidDays int

  Certpath string
  Keypath string

  Substractvaliditydays int
  Warnafterdays int
  Infoafterdays int
  Debugafterdays int
  ExpectWarn bool
  ExpectInfo bool
  ExpectDebug bool

}

func TestJorjiScanTlsExpiryWarnings(t *testing.T) {

  testsuite := []TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "1",
      Bind: "127.0.0.1:38491",
      Sni: "",
      ValidDays: 50,
      Certpath: "testtls1.pem",
      Keypath: "testtls1.key",
      Substractvaliditydays: 0,
      Warnafterdays: 30,
      Infoafterdays: 60,
      Debugafterdays: 90,
      ExpectWarn: false,
      ExpectInfo: true,
      ExpectDebug: false,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "2",
      Bind: "127.0.0.1:38492",
      Sni: "",
      ValidDays: 10,
      Certpath: "testtls2.cert",
      Keypath: "testtls2.key",
      Substractvaliditydays: 2,
      Warnafterdays: 10,
      Infoafterdays: 20,
      Debugafterdays: 30,
      ExpectWarn: true,
      ExpectInfo: false,
      ExpectDebug: false,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "3",
      Bind: "127.0.0.1:38493",
      Sni: "",
      ValidDays: 15,
      Certpath: "testtls3.cert",
      Keypath: "testtls3.key",
      Substractvaliditydays: 6,
      Warnafterdays: 10,
      Infoafterdays: 12,
      Debugafterdays: 14,
      ExpectWarn: true,
      ExpectInfo: false,
      ExpectDebug: false,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "4",
      Bind: "127.0.0.1:38494",
      Sni: "",
      ValidDays: 66,
      Certpath: "testtls4.cert",
      Keypath: "testtls4.key",
      Substractvaliditydays: 0,
      Warnafterdays: 10,
      Infoafterdays: 30,
      Debugafterdays: 70,
      ExpectWarn: false,
      ExpectInfo: false,
      ExpectDebug: true,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "5",
      Bind: "127.0.0.1:38495",
      Sni: "",
      ValidDays: 999,
      Certpath: "testtls5.cert",
      Keypath: "testtls5.key",
      Substractvaliditydays: 99,
      Warnafterdays: 50,
      Infoafterdays: 100,
      Debugafterdays: 150,
      ExpectWarn: false,
      ExpectInfo: false,
      ExpectDebug: false,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Name: "6",
      Bind: "127.0.0.1:38496",
      Sni: "",
      ValidDays: 5,
      Certpath: "testtls6.cert",
      Keypath: "testtls6.key",
      Substractvaliditydays: 9,
      Warnafterdays: 3,
      Infoafterdays: 4,
      Debugafterdays: 10,
      ExpectWarn: true,
      ExpectInfo: false,
      ExpectDebug: false,
    },
  }

  for _, test := range testsuite {

    tlsTestHelper_Create_cert_and_key(test.Certpath, test.Keypath, test.ValidDays)
    defer tlsTestHelper_RemoveCertAndKey(test.Certpath, test.Keypath)

    var wg sync.WaitGroup
    go func() {
      wg.Add(1)

      mux := http.NewServeMux()
      mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
          w.Write([]byte("This is an example server.\n"))
      })
      cfg := &tls.Config{
          MinVersion:               tls.VersionTLS12,
          CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
          PreferServerCipherSuites: true,
          CipherSuites: []uint16{
              tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
              tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
          },
      }
      srv := &http.Server{
          Addr:         test.Bind,
          Handler:      mux,
          TLSConfig:    cfg,
          TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
      }
      srv.ListenAndServeTLS(test.Certpath, test.Keypath)

    }()
    defer wg.Done()

    Conf.Out.Warnafterdays = test.Warnafterdays
    Conf.Out.Infoafterdays = test.Infoafterdays
    Conf.Out.Debugafterdays = test.Debugafterdays

    scannerReq := TlsExpiryScanner{
      Connect: test.Bind,
      Substractvaliditydays: test.Substractvaliditydays,
      Comment: test.Name,
    }

    scannerResults := JorjiScanTlsExpiry(scannerReq)

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

//func TestJorjiScanTlsExpirySniHandling(t *testing.T) {
//
//  var testsuite []TestExpiryScanner_JorjiScanTlsExpiry_Testcase
//    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
//      Bind: "127.0.0.1:49381",
//      Sni: "example.org",
//      ValidDays: ,
//      Certpath "",
//      Keypath "",
//      Substractvaliditydays: ,
//      Warnafterdays: ,
//      Infoafterdays: ,
//      Debugafterdays: ,
//      ExpectWarn: ,
//      ExpectInfo: ,
//      ExpectDebug: ,
//    },
//    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
//      Bind: "127.0.0.1:49381",
//      Sni: "hello.com",
//      ValidDays: ,
//      Certpath "",
//      Keypath "",
//      Substractvaliditydays: ,
//      Warnafterdays: ,
//      Infoafterdays: ,
//      Debugafterdays: ,
//      ExpectWarn: ,
//      ExpectInfo: ,
//      ExpectDebug: ,
//    },
//    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
//      Bind: "127.0.0.1:49381",
//      Sni: "ww.ch",
//      ValidDays: ,
//      Certpath "",
//      Keypath "",
//      Substractvaliditydays: ,
//      Warnafterdays: ,
//      Infoafterdays: ,
//      Debugafterdays: ,
//      ExpectWarn: ,
//      ExpectInfo: ,
//      ExpectDebug: ,
//    },
//  }
//
//}
//
//
//func TestJorjiScanTlsExpiryEnforcedMtlsHandling(t *testing.T) {
//}
//


func tlsTestHelper_RemoveCertAndKey(certPath string, keyPath string) () {

  err := os.Remove(certPath)
  if err != nil {
    log.Fatal(err)
  }

  err = os.Remove(keyPath)
  if err != nil {
    log.Fatal(err)
  }

}


func tlsTestHelper_Create_cert_and_key(certPath string, keyPath string, validForDays int) () {

  priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
  if err != nil {
    log.Fatal(err)
  }

  privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
  if err != nil {
    log.Fatal(err)
  }

  privOut := &bytes.Buffer{}
  pem.Encode(privOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
  pByteArr, _ := ioutil.ReadAll(privOut)
  err = ioutil.WriteFile(keyPath, pByteArr, 0600)
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

    IsCA:                  true,
    KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
    ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
    BasicConstraintsValid: true,
  }
  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, tlsTestHelper_keyType(priv), priv)
  if err != nil {
    log.Fatal(err)
  }
  out := &bytes.Buffer{}
  pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  bytes, _ := ioutil.ReadAll(out)
  err = ioutil.WriteFile(certPath, bytes, 0644)
  if err != nil {
    log.Fatal(err)
  }

  return

}

func tlsTestHelper_keyType(priv interface{}) interface{} {
  switch k := priv.(type) {
  case *rsa.PrivateKey:
    return &k.PublicKey
  case *ecdsa.PrivateKey:
    return &k.PublicKey
  default:
    return nil
  }
}

