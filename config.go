package main

import (
)


type Config struct {

  // Debugging messages in trace facility
  Debug bool

  // Configure Splunk HEC sender
  Hec HecSender

  // Configre list of filescanner
  ScanFiles []FileScanner

  // Console Output Control
  ConsoleOut ScanOutput

  // Interval for sleep if started as server
  ServerIntervalMinutes int

}


type HecSender struct {

  // set to true to enable HEC output (messages are NOT chunked
  // they are emitted for every line
  Enabled bool

  // https HEC Host
  Host string

  // TLS security
  TLSChainCheck bool

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
  RestrictCN string

  // if true, any certificate in the file that is marked as CA is ignored
  RestrictNoCa bool

  // if set, this amount of days will be substracted from the NotValidAfter
  // field, before the calculation of remaining days is done
  SubstractValidityDays bool

}


type ScanOutput struct {

  // Quiet mode, surpresses stdout
  SilenceStdout bool

  // Configure, after how many days left a message is sent to which facility
  WarnAfterDays int
  InfoAfterDays int
  DebugAfterDays int

  // If we send to console, control if warnings go to stderr
  // (by default, only programmatic errors go to stderr)
  WarnToStdErr bool
  InfoToStdErr bool
  DebugToStdErr bool

  // If we are running in exec mode, control if findings trigger a non-zero exit
  // (by default, only programmatic errors trigger a non-zero exit)
  // if enabled the exit codes are:
  // More than 0 Warns: Exit with 20
  // More than 0 Infos: Exit with 30
  // More than 0 Debugs: Exit with 40
  WarnExitCodes bool
  InfoExitCodes bool
  DebugExitCodes bool

}
