package netaccept

import (
	"net"
)

// A Handler responds to an incoming connection.
type Handler interface {
	Serve(conn net.Conn)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as
// handlers. If f is a function with the appropriate signature, HandlerFunc(f)
// is a Handler that calls f.
type HandlerFunc func(conn net.Conn)

// Serve calls f(conn)
func (f HandlerFunc) Serve(conn net.Conn) {
	f(conn)
}
