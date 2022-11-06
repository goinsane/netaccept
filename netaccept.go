// Package netaccept provides NetAccept struct for accepting connections from net.Listener.
package netaccept

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// An NetAccept defines parameters to accept connections.
// It is similar with GoLang's http.Server.
type NetAccept struct {
	// Handler to invoke.
	Handler Handler

	// TLSConfig optionally provides a TLS configuration.
	TLSConfig *tls.Config

	// MaxConn provides maximum connection count. If it is zero, max connection is unlimited.
	MaxConn int

	mu           sync.RWMutex
	lis          net.Listener
	lisCloseOnce sync.Once
	lisCloseErr  error
	ctx          context.Context
	ctxCancel    context.CancelFunc
	conns        map[net.Conn]struct{}
	connsMu      sync.RWMutex
}

// Shutdown gracefully shuts down the NetAccept without interrupting any
// connections. Shutdown works by first closing the NetAccept's underlying Listener, then
// cancels the context on Serve method of Handler, and then waiting indefinitely for
// connections to exit Serve method of Handler and then close. If the provided
// context expires before the shutdown is complete, Shutdown returns the
// context's error, otherwise it returns any error returned from closing the
// NetAccept's underlying Listener.
//
// When Shutdown is called, Serve, ServeTLS, ListenAndServe, and ListenAndServeTLS
// immediately return nil. Make sure the program doesn't exit and waits
// instead for Shutdown to return.
func (a *NetAccept) Shutdown(ctx context.Context) (err error) {
	err = a.cancel()

	for {
		select {
		case <-time.After(5 * time.Millisecond):
			a.connsMu.RLock()
			if len(a.conns) <= 0 {
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

// Close immediately closes the NetAccept's underlying Listener and any connections.
// For a graceful shutdown, use Shutdown.
//
// Close returns any error returned from closing the NetAccept's underlying
// Listener.
func (a *NetAccept) Close() (err error) {
	err = a.cancel()

	a.connsMu.RLock()
	for conn := range a.conns {
		conn.Close()
	}
	a.connsMu.RUnlock()

	return
}

// ListenAndServe listens on the given network and address; and then calls
// Serve to handle incoming connections. ListenAndServe returns a
// nil error after Close or Shutdown method called.
func (a *NetAccept) ListenAndServe(network, address string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return a.Serve(lis)
}

// ListenAndServeTLS listens on the given network and address; and
// then calls ServeTLS to handle incoming TLS connections.
//
// Filenames containing a certificate and matching private key for the
// NetAccept must be provided if neither the NetAccept's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the NetAccept's certificate, any intermediates, and
// the CA's certificate.
func (a *NetAccept) ListenAndServeTLS(network, address string, certFile, keyFile string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return a.ServeTLS(lis, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener lis, creating a new service
// goroutine for each. The service goroutines read requests and then call
// a.Handler to reply to them. Serve always closes lis unless returned error
// is ErrAlreadyServed. Serve returns a nil error after Close or
// Shutdown method called.
func (a *NetAccept) Serve(lis net.Listener) error {
	var err error

	a.mu.Lock()
	if a.lis != nil {
		a.mu.Unlock()
		return ErrAlreadyServed
	}
	a.lis = lis
	a.ctx, a.ctxCancel = context.WithCancel(context.Background())
	a.mu.Unlock()

	a.connsMu.Lock()
	a.conns = make(map[net.Conn]struct{})
	a.connsMu.Unlock()

	defer a.cancel()

	for a.ctx.Err() == nil {
		if a.MaxConn > 0 {
			a.connsMu.RLock()
			connCount := len(a.conns)
			a.connsMu.RUnlock()
			if connCount >= a.MaxConn {
				select {
				case <-a.ctx.Done():
					return nil
				case <-time.After(5 * time.Millisecond):
				}
				continue
			}
		}

		var conn net.Conn
		conn, err = lis.Accept()
		if err != nil {
			if a.ctx.Err() != nil {
				return nil
			}
			return err
		}

		go a.serve(conn)
	}

	return nil
}

// ServeTLS accepts incoming connections on the Listener lis, creating a
// new service goroutine for each. The service goroutines read requests and
// then call a.Handler to reply to them. ServeTLS always closes lis unless returned error
// is ErrAlreadyServed or as TLSError. ServeTLS returns a nil error after
// Close or Shutdown method called.
//
// Additionally, files containing a certificate and matching private key for
// the NetAccept must be provided if neither the NetAccept's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is signed by
// a certificate authority, the certFile should be the concatenation of the
// NetAccept's certificate, any intermediates, and the CA's certificate.
func (a *NetAccept) ServeTLS(lis net.Listener, certFile, keyFile string) (err error) {
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
			err = wrapTLSError(err)
			return
		}
	}

	return a.Serve(tls.NewListener(lis, config))
}

// serve serves connection to handler.
func (a *NetAccept) serve(conn net.Conn) {
	a.connsMu.Lock()
	a.conns[conn] = struct{}{}
	a.connsMu.Unlock()

	a.Handler.Serve(a.ctx, conn)

	conn.Close()

	a.connsMu.Lock()
	delete(a.conns, conn)
	a.connsMu.Unlock()
}

// cancel cancels serving operation and closes listener once, then returns closing error.
func (a *NetAccept) cancel() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.lis == nil {
		return nil
	}
	a.ctxCancel()
	a.lisCloseOnce.Do(func() {
		a.lisCloseErr = a.lis.Close()
	})
	return a.lisCloseErr
}
