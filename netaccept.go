// Package netaccept provides NetAccept struct for accepting connections from net.Listener.
package netaccept

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// An NetAccept defines parameters to accept connections.
// It is similar with GoLang's http.Server.
type NetAccept struct {
	// Handler to invoke.
	Handler Handler

	// TLSConfig optionally provides a TLS configuration.
	TLSConfig *tls.Config

	mu           sync.RWMutex
	lis          net.Listener
	lisCloseOnce *sync.Once
	lisCloseErr  error
	ctx          context.Context
	ctxCancel    context.CancelFunc
	conns        map[net.Conn]struct{}
	connsMu      sync.RWMutex
}

var (
	maxTempDelay time.Duration
)

// SetMaxTempDelay sets maximum temporary error wait duration as concurrent-safe.
// Zero or negative values mean to wait forever. By default, zero.
func SetMaxTempDelay(d time.Duration) {
	atomic.StoreInt64((*int64)(&maxTempDelay), int64(d))
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
func (a *NetAccept) Serve(lis net.Listener) (err error) {
	a.mu.Lock()
	if a.lis != nil {
		err = ErrAlreadyServed
		a.mu.Unlock()
		return
	}
	a.lis = lis
	a.lisCloseOnce = new(sync.Once)
	a.ctx, a.ctxCancel = context.WithCancel(context.Background())
	a.mu.Unlock()

	a.connsMu.Lock()
	a.conns = make(map[net.Conn]struct{})
	a.connsMu.Unlock()

	defer a.cancel()

	var tempDelay, totalDelay time.Duration
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
				maxDelay := time.Duration(atomic.LoadInt64((*int64)(&maxTempDelay)))
				if maxDelay > 0 && totalDelay > maxDelay {
					return
				}
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				time.Sleep(tempDelay)
				totalDelay += tempDelay
				continue
			}
			return
		}
		tempDelay = 0
		totalDelay = 0
		go a.serve(conn)
	}
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
