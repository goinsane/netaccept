package netaccept

import (
	"context"
	"net"
)

// A Handler responds to an incoming connection.
type Handler interface {
	Serve(ctx context.Context, conn net.Conn)
}

// The HandlerFunc type is an adapter to allow the use of ordinary functions as
// handlers. If f is a function with the appropriate signature, HandlerFunc(f)
// is a Handler that calls f.
type HandlerFunc func(ctx context.Context, conn net.Conn)

// Serve calls f(ctx, conn)
func (f HandlerFunc) Serve(ctx context.Context, conn net.Conn) {
	f(ctx, conn)
}
