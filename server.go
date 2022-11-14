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

	mu           sync.RWMutex
	lis          net.Listener
	lisCloseOnce sync.Once
	lisCloseErr  error
	ctx          context.Context
	ctxCancel    context.CancelFunc
	conns        map[net.Conn]struct{}
	connsMu      sync.RWMutex
}

// Shutdown gracefully shuts down the Server without interrupting any
// connections. Shutdown works by first closing the Server's underlying Listener, then
// cancels the context on Serve method of Handler, and then waiting indefinitely for
// connections to exit Serve method of Handler and then close. If the provided
// context expires before the shutdown is complete, Shutdown returns the
// context's error, otherwise it returns any error returned from closing the
// Server's underlying Listener.
//
// When Shutdown is called, Serve, ServeTLS, ListenAndServe, and ListenAndServeTLS
// immediately return nil. Make sure the program doesn't exit and waits
// instead for Shutdown to return.
func (s *Server) Shutdown(ctx context.Context) (err error) {
	err = s.cancel()

	for {
		select {
		case <-time.After(5 * time.Millisecond):
			s.connsMu.RLock()
			if len(s.conns) <= 0 {
				s.connsMu.RUnlock()
				return
			}
			s.connsMu.RUnlock()
		case <-ctx.Done():
			s.connsMu.RLock()
			for conn := range s.conns {
				conn.Close()
			}
			s.connsMu.RUnlock()
			err = ctx.Err()
			return
		}
	}
}

// Close immediately closes the Server's underlying Listener and any connections.
// For a graceful shutdown, use Shutdown.
//
// Close returns any error returned from closing the Server's underlying
// Listener.
func (s *Server) Close() (err error) {
	err = s.cancel()

	s.connsMu.RLock()
	for conn := range s.conns {
		conn.Close()
	}
	s.connsMu.RUnlock()

	return
}

// ListenAndServe listens on the given network and address; and then calls
// Serve to handle incoming connections. ListenAndServe returns a
// nil error after Close or Shutdown method called.
func (s *Server) ListenAndServe(network, address string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return s.Serve(lis)
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
func (s *Server) ListenAndServeTLS(network, address string, certFile, keyFile string) error {
	lis, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer lis.Close()
	return s.ServeTLS(lis, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener lis, creating a new service
// goroutine for each. The service goroutines read requests and then call
// a.Handler to reply to them. Serve always closes lis unless returned error
// is ErrAlreadyServed. Serve returns a nil error after Close or
// Shutdown method called.
func (s *Server) Serve(lis net.Listener) error {
	var err error

	s.mu.Lock()
	if s.lis != nil {
		s.mu.Unlock()
		return ErrAlreadyServed
	}
	s.lis = lis
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	s.mu.Unlock()

	s.connsMu.Lock()
	s.conns = make(map[net.Conn]struct{})
	s.connsMu.Unlock()

	defer s.cancel()

	for s.ctx.Err() == nil {
		if s.MaxConn > 0 {
			s.connsMu.RLock()
			connCount := len(s.conns)
			s.connsMu.RUnlock()
			if connCount >= s.MaxConn {
				select {
				case <-s.ctx.Done():
					return nil
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
				case <-s.ctx.Done():
					return nil
				case <-time.After(5 * time.Millisecond):
				}
				continue
			}
			if s.ctx.Err() != nil {
				return nil
			}
			return err
		}

		go s.serve(conn)
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
// the Server must be provided if neither the Server's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is signed by
// a certificate authority, the certFile should be the concatenation of the
// Server's certificate, any intermediates, and the CA's certificate.
func (s *Server) ServeTLS(lis net.Listener, certFile, keyFile string) error {
	var err error

	var config *tls.Config
	if s.TLSConfig != nil {
		config = s.TLSConfig.Clone()
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

	return s.Serve(tls.NewListener(lis, config))
}

// serve serves connection to handler.
func (s *Server) serve(conn net.Conn) {
	s.connsMu.Lock()
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()

	s.Handler.Serve(s.ctx, conn)

	conn.Close()

	s.connsMu.Lock()
	delete(s.conns, conn)
	s.connsMu.Unlock()
}

// cancel cancels serving operation and closes listener once, then returns closing error.
func (s *Server) cancel() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lis == nil {
		return nil
	}
	s.ctxCancel()
	s.lisCloseOnce.Do(func() {
		s.lisCloseErr = s.lis.Close()
	})
	return s.lisCloseErr
}
