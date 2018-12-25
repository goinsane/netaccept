// Package accepter provides an Accepter and utilities for net.Listener.
package accepter

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"time"
)

// An Accepter defines parameters to accept connections. It seems like
// GoLang's http.Server.
type Accepter struct {
	// Handler to invoke.
	Handler Handler

	// TLSConfig optionally provides a TLS configuration.
	TLSConfig *tls.Config

	// ErrorLog specifies an optional logger for errors in Handler.
	ErrorLog *log.Logger

	l       net.Listener
	conns   map[net.Conn]connData
	connsMu sync.RWMutex
	closeCh chan struct{}
}

type connData struct {
	conn    net.Conn
	closeCh chan struct{}
}

// Shutdown gracefully shuts down the Accepter without interrupting any
// connections. Shutdown works by first closing the Accepter's underlying Listener, then
// fills closeCh on Serve method of Handler, and then waiting indefinitely for
// connections to exit Serve method of Handler and then close. If the provided
// context expires before the shutdown is complete, Shutdown returns the
// context's error, otherwise it returns any error returned from closing the
// Accepter's underlying Listener.
//
// When Shutdown is called, Serve, TCPListenAndServe, and TCPListenAndServeTLS
// immediately return nil. Make sure the program doesn't exit and waits
// instead for Shutdown to return.
func (a *Accepter) Shutdown(ctx context.Context) (err error) {
	err = a.l.Close()
	select {
	case a.closeCh <- struct{}{}:
	default:
	}

	a.connsMu.RLock()
	for _, c := range a.conns {
		select {
		case c.closeCh <- struct{}{}:
		default:
		}
	}
	a.connsMu.RUnlock()

	for {
		select {
		case <-time.After(5 * time.Millisecond):
			a.connsMu.RLock()
			if len(a.conns) == 0 {
				a.connsMu.RUnlock()
				return
			}
			a.connsMu.RUnlock()
		case <-ctx.Done():
			a.connsMu.RLock()
			for _, c := range a.conns {
				c.conn.Close()
			}
			a.connsMu.RUnlock()
			err = ctx.Err()
			return
		}
	}
}

// Close immediately closes the Accepter's underlying Listener and any connections.
// For a graceful shutdown, use Shutdown.
//
// Close returns any error returned from closing the Accepter's underlying
// Listener.
func (a *Accepter) Close() (err error) {
	err = a.l.Close()
	select {
	case a.closeCh <- struct{}{}:
	default:
	}

	a.connsMu.RLock()
	for _, c := range a.conns {
		select {
		case c.closeCh <- struct{}{}:
		default:
		}
		c.conn.Close()
	}
	a.connsMu.RUnlock()

	return
}

// TCPListenAndServe listens on the TCP network address addr and then calls
// Serve to handle requests on incoming connections. TCPListenAndServe returns a
// nil error after Close or Shutdown method called.
func (a *Accepter) TCPListenAndServe(addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return a.Serve(l)
}

// TCPListenAndServeTLS listens on the TCP network address addr and
// then calls Serve to handle requests on incoming TLS connections.
//
// Filenames containing a certificate and matching private key for the
// Accepter must be provided if neither the Accepter's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the Accepter's certificate, any intermediates, and
// the CA's certificate.
func (a *Accepter) TCPListenAndServeTLS(addr string, certFile, keyFile string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return a.ServeTLS(l, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener l, creating a new service
// goroutine for each. The service goroutines read requests and then call
// a.Handler to reply to them. Serve returns a nil error after Close or
// Shutdown method called.
func (a *Accepter) Serve(l net.Listener) (err error) {
	a.l = l
	a.conns = make(map[net.Conn]connData)
	a.closeCh = make(chan struct{}, 1)
	defer func() {
		a.l.Close()
	}()
	for {
		var conn net.Conn
		conn, err = l.Accept()
		if err != nil {
			select {
			case <-a.closeCh:
				err = nil
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return
		}
		go a.serve(conn)
	}
}

// ServeTLS accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines read requests and
// then call a.Handler to reply to them. ServeTLS returns a nil error after
// Close or Shutdown method called.
//
// Additionally, files containing a certificate and matching private key for
// the Accepter must be provided if neither the Accepter's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is signed by
// a certificate authority, the certFile should be the concatenation of the
// Accepter's certificate, any intermediates, and the CA's certificate.
func (a *Accepter) ServeTLS(l net.Listener, certFile, keyFile string) (err error) {
	config := a.TLSConfig
	if config == nil {
		config = &tls.Config{}
	}
	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return
		}
	}
	tlsListener := tls.NewListener(l, config)
	return a.Serve(tlsListener)
}

func (a *Accepter) serve(conn net.Conn) {
	closeCh := make(chan struct{}, 1)

	a.connsMu.Lock()
	a.conns[conn] = connData{
		conn:    conn,
		closeCh: closeCh,
	}
	a.connsMu.Unlock()

	if a.Handler != nil {
		errorLog := a.ErrorLog
		if errorLog == nil {
			errorLog = log.New(ioutil.Discard, "", log.LstdFlags)
		}
		func() {
			defer func() {
				e := recover()
				if e != nil {
					errorLog.Print(e)
				}
			}()
			a.Handler.Serve(conn, closeCh)
		}()
	}

	conn.Close()

	a.connsMu.Lock()
	delete(a.conns, conn)
	a.connsMu.Unlock()
}
