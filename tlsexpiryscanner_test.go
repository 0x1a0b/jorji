package main

import (
)


type TestExpiryScanner_JorjiScanTlsExpiry_Testcase struct {

  Bind string
  Sni string
  ValidDays int

  Substractvaliditydays int
  Warnafterdays int
  Infoafterdays int
  Debugafterdays int
  ExpectWarn bool
  ExpectInfo bool
  ExpectDebug bool

}

func TestJorjiScanTlsExpiryWarnings(t *testing.T) {

  var testsuite []TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38491",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38492",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38493",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38494",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38495",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:38496",
      Sni: "",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
  }

}

func TestJorjiScanTlsExpirySniHandling(t *testing.T) {

  var testsuite []TestExpiryScanner_JorjiScanTlsExpiry_Testcase
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:49381",
      Sni: "example.org",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:49381",
      Sni: "hello.com",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
    TestExpiryScanner_JorjiScanTlsExpiry_Testcase{
      Bind: "127.0.0.1:49381",
      Sni: "ww.ch",
      ValidDays: ,
      Substractvaliditydays: ,
      Warnafterdays: ,
      Infoafterdays: ,
      Debugafterdays: ,
      ExpectWarn: ,
      ExpectInfo: ,
      ExpectDebug: ,
    },
  }

}


func TestJorjiScanTlsExpiryEnforcedMtlsHandling(t *testing.T) {
}

