# accepter

[![GoDoc](https://godoc.org/github.com/goinsane/accepter?status.svg)](https://godoc.org/github.com/goinsane/accepter)

Package accepter provides an Accepter and utilities for net.Listener.
It is similar with GoLang's http.Server.

## v1.2 changes from v1.0

* using cancelling context instead of channel
* changed Handler.Serve arguments to (ctx, conn) from (conn, closeCh)
* removed panic recovering for Handler.Serve(...)
* removed Accepter.ErrorLog
* added ListenAndServe and ListenAndServeTLS instead of TCPListenAndServe and TCPListenAndServeTLS
* added go.mod support
* added SetMaxTempDelay(...)
