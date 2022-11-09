package main

import (
	"context"
	"log"
	"net"

	"github.com/goinsane/netaccept"
)

func main() {
	a := &netaccept.Server{
		Handler: netaccept.HandlerFunc(func(ctx context.Context, conn net.Conn) {
			log.Printf("connection accepted %q -> %q", conn.RemoteAddr(), conn.LocalAddr())
			defer log.Printf("connection ended %q -> %q", conn.RemoteAddr(), conn.LocalAddr())
			for {
				b := make([]byte, 32*1024)
				n, err := conn.Read(b[:])
				if err != nil {
					break
				}
				m, err := conn.Write(b[:n])
				if err != nil {
					break
				}
				if m < n {
					break
				}
			}
		}),
	}
	log.Fatal(a.ListenAndServe("tcp", ":1234"))
}
