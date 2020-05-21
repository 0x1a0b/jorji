package main

import (
)


type Config struct {

  // Debugging messages in trace facility
  Debug bool `default:"true"`

  // Configure Splunk HEC sender
  Hec HecSender

  // Configre list of filescanner
  Scanfiles []FileScanner

  // Output Control
  Out ScanOutput

  // Interval for sleep if started as server
  Serverintervalminutes int `default:"120"`

}


type HecSender struct {

  // set to true to enable HEC output (messages are NOT chunked
  // they are emitted for every line
  Enabled bool `default:"false"`

  // https HEC Host
  Host string

  // TLS security
  Tlschaincheck bool `default:"true"`

  // HEC SecretID
  Secret string

  // Target Index
  Index string

  // Target Sourcetype
  Sourcetype string

}


type FileScanner struct {

  // required: path where the cert is
  // if there are multiple certs found in the file, the first is taken
  Path string

  // if set and multiple certs are in the file, the first cert matching CN will be taken
  Restrictcn string

  // if true, any certificate in the file that is marked as CA is ignored
  Restrictnoca bool `default:"false"`

  // if set, this amount of days will be substracted from the NotValidAfter
  // field, before the calculation of remaining days is done
  Substractvaliditydays int `default:"0"`

}


type ScanOutput struct {

  // Configure, after how many days left a message is sent to which facility
  Warnafterdays int `default:"42"`
  Infoafterdays int `default:"62"`
  Debugafterdays int `default:"82"`

  // If we are running in exec mode, control if findings trigger a non-zero exit
  // (by default, only programmatic errors trigger a non-zero exit)
  // if enabled the exit codes are:
  // More than 0 Warns: Exit with 40
  // More than 0 Infos: Exit with 30
  // More than 0 Debugs: Exit with 30
  Warnexitcodes bool `default:"false"`
  Infoexitcodes bool `default:"false"`
  Debugexitcodes bool `default:"false"`

}
