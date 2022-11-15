package netaccept

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"
)

// An Server defines parameters to accept connections.
// It is similar with GoLang's http.Server.
type Server struct {
	// Handler to invoke.
	Handler Handler

	// TLSConfig optionally provides a TLS configuration.
	TLSConfig *tls.Config

	// MaxConn provides maximum connection count. If it is zero, max connection is unlimited.
	MaxConn int

	mu          sync.Mutex
	cancelled   bool
	initialized bool
	ctx         context.Context
	ctxCancel   context.CancelFunc
	listeners   []net.Listener

	conns   map[net.Conn]struct{}
	connsMu sync.RWMutex
}

// Shutdown gracefully shuts down the Server without interrupting any
// connections. Shutdown works by first closing all open listeners, and then waiting indefinitely for
// connections to exit Serve method of Handler and then shut down. If the provided
// context expires before the shutdown is complete, Shutdown returns the
// context's error, otherwise it returns any error returned from closing the
// Server's underlying Listener(s).
//
// When Shutdown is called, Serve, ServeTLS, ListenAndServe, and ListenAndServeTLS
// immediately return ErrServerClosed. Make sure the program doesn't exit and waits
// instead for Shutdown to return.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (srv *Server) Shutdown(ctx context.Context) (err error) {
	err = srv.cancel()

	for {
		select {
		case <-time.After(5 * time.Millisecond):
			srv.connsMu.RLock()
			if len(srv.conns) <= 0 {
				srv.connsMu.RUnlock()
				return
			}
			srv.connsMu.RUnlock()
		case <-ctx.Done():
			srv.connsMu.RLock()
			for conn := range srv.conns {
				conn.Close()
			}
			srv.connsMu.RUnlock()
			err = ctx.Err()
			return
		}
	}
}

// Close immediately closes all active net.Listeners and any connections.
// For a graceful shutdown, use Shutdown.
//
// Close returns any error returned from closing the Server's underlying
// Listener(s).
//
// When Close is called, Serve, ServeTLS, ListenAndServe, and ListenAndServeTLS
// immediately return ErrServerClosed.
//
// Once Close has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (srv *Server) Close() (err error) {
	err = srv.cancel()

	srv.connsMu.RLock()
	for conn := range srv.conns {
		conn.Close()
	}
	srv.connsMu.RUnlock()

	return
}

// ListenAndServe listens on the given network and address; and then calls Serve to handle incoming connections.
//
// ListenAndServe always returns a non-nil error. After Shutdown or Close, the returned error is ErrServerClosed.
func (srv *Server) ListenAndServe(network, address string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return srv.Serve(lis)
}

// ListenAndServeTLS listens on the given network and address; and
// then calls ServeTLS to handle incoming TLS connections.
//
// Filenames containing a certificate and matching private key for the
// Server must be provided if neither the Server's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the Server's certificate, any intermediates, and
// the CA's certificate.
//
// ListenAndServeTLS always returns a non-nil error. After Shutdown or Close, the returned error is ErrServerClosed.
func (srv *Server) ListenAndServeTLS(network, address string, certFile, keyFile string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return srv.ServeTLS(lis, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener lis, creating a new service
// goroutine for each. The service goroutines read requests and then call
// srv.Handler to reply to them.
//
// Serve always returns a non-nil error and closes lis. After Shutdown or Close,
// the returned error is ErrServerClosed.
func (srv *Server) Serve(lis net.Listener) error {
	var err error

	defer lis.Close()

	srv.mu.Lock()
	if srv.cancelled {
		srv.mu.Unlock()
		return ErrServerClosed
	}
	if !srv.initialized {
		srv.initialized = true
		srv.ctx, srv.ctxCancel = context.WithCancel(context.Background())
		srv.listeners = make([]net.Listener, 0, 4096)
	}
	srv.listeners = append(srv.listeners, &onceCloseListener{Listener: lis})
	srv.mu.Unlock()

	srv.connsMu.Lock()
	srv.conns = make(map[net.Conn]struct{})
	srv.connsMu.Unlock()

	for srv.ctx.Err() == nil {
		if srv.MaxConn > 0 {
			srv.connsMu.RLock()
			connCount := len(srv.conns)
			srv.connsMu.RUnlock()
			if connCount >= srv.MaxConn {
				select {
				case <-srv.ctx.Done():
					return ErrServerClosed
				case <-time.After(5 * time.Millisecond):
				}
				continue
			}
		}

		var conn net.Conn
		conn, err = lis.Accept()
		if err != nil {
			if oe, ok := err.(*net.OpError); ok && oe.Temporary() {
				select {
				case <-srv.ctx.Done():
					return ErrServerClosed
				case <-time.After(5 * time.Millisecond):
				}
				continue
			}
			if srv.ctx.Err() != nil {
				return ErrServerClosed
			}
			return err
		}

		go srv.serve(conn)
	}

	return ErrServerClosed
}

// ServeTLS accepts incoming connections on the Listener lis, creating a
// new service goroutine for each. The service goroutines read requests and
// then call srv.Handler to reply to them.
//
// Files containing a certificate and matching private key for
// the Server must be provided if neither the Server's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is signed by
// a certificate authority, the certFile should be the concatenation of the
// server's certificate, any intermediates, and the CA's certificate.
//
// ServeTLS always closes lis unless returned error is TLSError.
// ServeTLS always returns a non-nil error. After Shutdown or Close, the returned error is ErrServerClosed.
func (srv *Server) ServeTLS(lis net.Listener, certFile, keyFile string) error {
	var err error

	var config *tls.Config
	if srv.TLSConfig != nil {
		config = srv.TLSConfig.Clone()
	} else {
		config = &tls.Config{}
	}

	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return wrapTLSError(err)
		}
	}

	return srv.Serve(tls.NewListener(lis, config))
}

// serve serves connection to handler.
func (srv *Server) serve(conn net.Conn) {
	srv.connsMu.Lock()
	srv.conns[conn] = struct{}{}
	srv.connsMu.Unlock()

	srv.Handler.Serve(conn)

	conn.Close()

	srv.connsMu.Lock()
	delete(srv.conns, conn)
	srv.connsMu.Unlock()
}

// cancel cancels serving operation and closes listener once, then returns closing error.
func (srv *Server) cancel() (err error) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.cancelled {
		return nil
	}
	srv.cancelled = true
	if !srv.initialized {
		return nil
	}
	srv.ctxCancel()
	for _, lis := range srv.listeners {
		if l, ok := lis.(*onceCloseListener); ok {
			err = l.Close()
		} else {
			err = lis.Close()
		}
	}
	return
}
