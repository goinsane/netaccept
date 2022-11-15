package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/goinsane/netaccept"
)

func main() {
	srv := &netaccept.Server{
		Handler: netaccept.HandlerFunc(func(conn net.Conn) {
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
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
		defer cancel()
		<-ctx.Done()
		termCtx, termCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer termCancel()
		err := srv.Shutdown(termCtx)
		if err != nil {
			log.Print(fmt.Errorf("shutdown error: %w", err))
		}
	}()
	err := srv.ListenAndServe("tcp", ":1234")
	if err != netaccept.ErrServerClosed {
		log.Print(err)
	}
	wg.Wait()
}
