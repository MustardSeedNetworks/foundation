// SPDX-License-Identifier: BUSL-1.1

package httpserver

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// tlsHandshakeRecord is the first byte of a TLS ClientHello (ContentType
// handshake, RFC 8446 §5.1). No HTTP request line can start with it: 0x16 is
// SYN, not a method character.
const tlsHandshakeRecord = 0x16

// defaultRedirectTimeout bounds how long a connection may stay silent before
// the wrapper gives up on it. A connection that says nothing costs one
// goroutine and one file descriptor until it speaks.
const defaultRedirectTimeout = 10 * time.Second

// maxRedirectRequestBytes bounds the plaintext request the wrapper will read
// before answering. It only needs the request line and the Host header; a
// client that sends more than this is not a browser that mistyped a scheme.
const maxRedirectRequestBytes = 8 << 10

// RedirectOptions configures [PlaintextRedirect].
type RedirectOptions struct {
	// Host is the authority used in the Location URL when the request carries
	// no Host header (HTTP/1.0). Empty means the listener's own address.
	Host string

	// Timeout bounds how long a connection may stay silent before it is
	// closed. Zero means defaultRedirectTimeout.
	Timeout time.Duration

	// Logger, when non-nil, records redirects at DEBUG. Redirects are a normal
	// browser mistake, not an incident.
	Logger *slog.Logger
}

// PlaintextRedirect wraps ln so that one port serves both the products' TLS
// and a redirect for operators who type `host:8443` without a scheme.
//
// Every connection is peeked one byte. A TLS ClientHello is handed to
// [net.Listener.Accept] unchanged, so the TLS server behind this sees exactly
// what it would have seen unwrapped. Anything else is read as one HTTP/1.x
// request and answered `308 Permanent Redirect` to the https URL, then closed:
// no other plaintext content is ever served, because these products are
// HTTPS-only and a plaintext path that returned content would be a downgrade.
// A 308 rather than a 301 because it preserves the method, and a form POST to
// a mistyped scheme must not silently become a GET.
//
// The peek runs per connection in its own goroutine, so a silent plaintext
// connection cannot stall the TLS clients queued behind it.
func PlaintextRedirect(ln net.Listener, opts RedirectOptions) net.Listener {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultRedirectTimeout
	}
	if opts.Host == "" {
		opts.Host = ln.Addr().String()
	}

	r := &redirectListener{
		Listener: ln,
		opts:     opts,
		accepted: make(chan net.Conn),
		done:     make(chan struct{}),
	}
	go r.pump()
	return r
}

type redirectListener struct {
	net.Listener
	opts     RedirectOptions
	accepted chan net.Conn
	done     chan struct{}
	closeErr error
	once     sync.Once
	wg       sync.WaitGroup
}

// pump owns the real accept loop. It never blocks on classifying a connection,
// so one slow client cannot delay the next.
func (r *redirectListener) pump() {
	defer close(r.accepted)
	for {
		conn, err := r.Listener.Accept()
		if err != nil {
			r.once.Do(func() {
				r.closeErr = err
				close(r.done)
			})
			r.wg.Wait()
			return
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.classify(conn)
		}()
	}
}

// classify peeks the first byte and either delivers the connection to Accept
// or answers the redirect and closes it.
func (r *redirectListener) classify(conn net.Conn) {
	if deadlineErr := conn.SetReadDeadline(time.Now().Add(r.opts.Timeout)); deadlineErr != nil {
		_ = conn.Close()
		return
	}

	reader := bufio.NewReader(conn)
	first, peekErr := reader.Peek(1)
	if peekErr != nil {
		_ = conn.Close()
		return
	}

	if first[0] == tlsHandshakeRecord {
		if clearErr := conn.SetReadDeadline(time.Time{}); clearErr != nil {
			_ = conn.Close()
			return
		}
		select {
		case r.accepted <- &bufferedConn{Conn: conn, reader: reader}:
		case <-r.done:
			_ = conn.Close()
		}
		return
	}

	r.redirect(conn, reader)
	_ = conn.Close()
}

// redirect answers one plaintext HTTP request with a 308. A request it cannot
// parse gets nothing: a port scanner learns no more than that the port is open.
func (r *redirectListener) redirect(conn net.Conn, reader *bufio.Reader) {
	req, readErr := http.ReadRequest(bufio.NewReader(io.LimitReader(reader, maxRedirectRequestBytes)))
	if readErr != nil {
		return
	}

	target := &url.URL{Scheme: "https", Host: r.authority(req), Path: req.URL.Path, RawQuery: req.URL.RawQuery}
	if target.Path == "" {
		target.Path = "/"
	}

	if r.opts.Logger != nil {
		r.opts.Logger.DebugContext(context.Background(),
			"redirected a plaintext request to https on the same port",
			"remote", conn.RemoteAddr().String(),
			"location", target.String(),
		)
	}

	if writeDeadlineErr := conn.SetWriteDeadline(time.Now().Add(r.opts.Timeout)); writeDeadlineErr != nil {
		return
	}
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		http.StatusPermanentRedirect, http.StatusText(http.StatusPermanentRedirect), target.String(),
	)
}

// authority picks the host for the Location URL: the client's own Host header
// when it sent one, so an operator behind a name keeps that name, and the
// listener's address otherwise.
func (r *redirectListener) authority(req *http.Request) string {
	if host := strings.TrimSpace(req.Host); host != "" {
		return host
	}
	return r.opts.Host
}

// Accept returns the next TLS connection. Plaintext never reaches the caller.
func (r *redirectListener) Accept() (net.Conn, error) {
	conn, ok := <-r.accepted
	if !ok {
		return nil, r.closeErr
	}
	return conn, nil
}

// bufferedConn returns the peeked byte to the reader that follows it.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
