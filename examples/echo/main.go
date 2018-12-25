// +build ignore

package main

import (
	"log"
	"net"

	accepter "github.com/orkunkaraduman/go-accepter"
)

func main() {
	a := &accepter.Accepter{
		Handler: accepter.HandlerFunc(func(conn net.Conn, closeCh <-chan struct{}) {
			for {
				var b [1]byte
				n, err := conn.Read(b[:])
				if err != nil {
					break
				}
				if n > 0 {
					n, err := conn.Write(b[:])
					if err != nil || n < 1 {
						break
					}
				}
			}
		}),
	}
	log.Fatal(a.TCPListenAndServe(":1234"))
}
