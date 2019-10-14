// Package accepter provides an Accepter and utilities for net.Listener.
package accepter

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// An Accepter defines parameters to accept connections.
// It is similar with GoLang's http.Server.
type Accepter struct {
	// Handler to invoke.
	Handler Handler

	// TLSConfig optionally provides a TLS configuration.
	TLSConfig *tls.Config

	// TemporaryErrorCount increments each temporary accept error
	TemporaryErrorCount uint64

	lis          net.Listener
	lisCloseOnce *sync.Once
	lisCloseErr  error
	ctx          context.Context
	ctxCancel    context.CancelFunc
	conns        map[net.Conn]struct{}
	connsMu      sync.RWMutex
}

// Shutdown gracefully shuts down the Accepter without interrupting any
// connections. Shutdown works by first closing the Accepter's underlying Listener, then
// cancels the context on Serve method of Handler, and then waiting indefinitely for
// connections to exit Serve method of Handler and then close. If the provided
// context expires before the shutdown is complete, Shutdown returns the
// context's error, otherwise it returns any error returned from closing the
// Accepter's underlying Listener.
//
// When Shutdown is called, Serve, ServeTLS, ListenAndServe, and ListenAndServeTLS
// immediately return nil. Make sure the program doesn't exit and waits
// instead for Shutdown to return.
func (a *Accepter) Shutdown(ctx context.Context) (err error) {
	a.ctxCancel()
	err = a.lisClose()

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
			for conn := range a.conns {
				conn.Close()
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
	a.ctxCancel()
	err = a.lisClose()

	a.connsMu.RLock()
	for conn := range a.conns {
		conn.Close()
	}
	a.connsMu.RUnlock()

	return
}

func (a *Accepter) lisClose() error {
	a.lisCloseOnce.Do(func() {
		a.lisCloseErr = a.lis.Close()
	})
	return a.lisCloseErr
}

// ListenAndServe listens on the given network and address; and then calls
// Serve to handle incoming connections. ListenAndServe returns a
// nil error after Close or Shutdown method called.
func (a *Accepter) ListenAndServe(network, address string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return a.Serve(lis)
}

// ListenAndServeTLS listens on the given network and address; and
// then calls Serve to handle incoming TLS connections.
//
// Filenames containing a certificate and matching private key for the
// Accepter must be provided if neither the Accepter's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the Accepter's certificate, any intermediates, and
// the CA's certificate.
func (a *Accepter) ListenAndServeTLS(network, address string, certFile, keyFile string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return a.ServeTLS(lis, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener lis, creating a new service
// goroutine for each. The service goroutines read requests and then call
// a.Handler to reply to them. Serve returns a nil error after Close or
// Shutdown method called.
func (a *Accepter) Serve(lis net.Listener) (err error) {
	a.lis = lis
	a.lisCloseOnce = new(sync.Once)
	defer a.lisClose()
	a.ctx, a.ctxCancel = context.WithCancel(context.Background())
	defer a.ctxCancel()
	a.conns = make(map[net.Conn]struct{})
	for {
		var conn net.Conn
		conn, err = lis.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				err = nil
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				atomic.AddUint64(&a.TemporaryErrorCount, 1)
				time.Sleep(5 * time.Millisecond)
				continue
			}
			return
		}
		go a.serve(conn)
	}
}

// ServeTLS accepts incoming connections on the Listener lis, creating a
// new service goroutine for each. The service goroutines read requests and
// then call a.Handler to reply to them. ServeTLS returns a nil error after
// Close or Shutdown method called.
//
// Additionally, files containing a certificate and matching private key for
// the Accepter must be provided if neither the Accepter's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is signed by
// a certificate authority, the certFile should be the concatenation of the
// Accepter's certificate, any intermediates, and the CA's certificate.
func (a *Accepter) ServeTLS(lis net.Listener, certFile, keyFile string) (err error) {
	var config *tls.Config
	if a.TLSConfig != nil {
		config = a.TLSConfig.Clone()
	} else {
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

	return a.Serve(tls.NewListener(lis, config))
}

func (a *Accepter) serve(conn net.Conn) {
	a.connsMu.Lock()
	a.conns[conn] = struct{}{}
	a.connsMu.Unlock()

	a.Handler.Serve(a.ctx, conn)

	conn.Close()

	a.connsMu.Lock()
	delete(a.conns, conn)
	a.connsMu.Unlock()
}
