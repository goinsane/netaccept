package netaccept

import (
	"errors"
	"fmt"
)

var (
	// ErrAlreadyServed is returned when Serve or ServeTLS method has been already called
	ErrAlreadyServed = errors.New("the accepter has already served")
)

// TLSError is returned when a method fails with TLS error
type TLSError struct {
	err error
}

func wrapTLSError(err error) error {
	return &TLSError{
		err: err,
	}
}

// Error is implementation of error
func (e *TLSError) Error() string {
	s := "tls error"
	if e.err == nil {
		return s
	}
	return fmt.Sprintf("%s: %v", s, e.err)
}

// Unwrap returns wrapped error
func (e *TLSError) Unwrap() error {
	return e.err
}
