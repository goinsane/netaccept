# accepter

[![GoDoc](https://godoc.org/github.com/orkunkaraduman/go-accepter?status.svg)](https://godoc.org/github.com/orkunkaraduman/go-accepter)

Package accepter provides an Accepter and utilities for net.Listener.
It is similar with GoLang's http.Server.

## Changes from v1

* removed Accepter.ErrorLog
* using context instead of closeCh
