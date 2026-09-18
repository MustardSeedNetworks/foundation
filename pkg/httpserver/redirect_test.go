// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// plaintextRoundTrip writes raw bytes to the wrapped listener and returns
// everything the server sent back before closing.
func plaintextRoundTrip(t *testing.T, addr, request string) string {
	t.Helper()
	conn := dial(t, addr)
	defer func() { _ = conn.Close() }()

	if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatalf("SetDeadline: %v", deadlineErr)
	}
	if _, writeErr := io.WriteString(conn, request); writeErr != nil {
		t.Fatalf("write: %v", writeErr)
	}
	response, readErr := io.ReadAll(conn)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	return string(response)
}

// wrapped starts a TLS server behind the redirect wrapper and returns its
// address together with a client that trusts the generated certificate. The
// handler answers every request with "served".
func wrapped(t *testing.T, opts httpserver.RedirectOptions) (string, *http.Client) {
	t.Helper()

	raw := listenLoopback(t)
	ln := httpserver.PlaintextRedirect(raw, opts)
	t.Cleanup(func() { _ = ln.Close() })

	dir := t.TempDir()
	cert, certErr := httpserver.EnsureCertificate(
		filepath.Join(dir, httpserver.DefaultCertFileName),
		filepath.Join(dir, httpserver.DefaultKeyFileName),
		httpserver.CertOptions{DNSNames: []string{"localhost"}},
	)
	if certErr != nil {
		t.Fatalf("EnsureCertificate: %v", certErr)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "served")
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	return raw.Addr().String(), trusting(t, filepath.Join(dir, httpserver.DefaultCertFileName))
}

// trusting builds a client that verifies the server against the certificate
// it generated. InsecureSkipVerify would make every one of these tests pass
// against a server presenting anything at all.
func trusting(t *testing.T, certPath string) *http.Client {
	t.Helper()
	pemBytes, readErr := os.ReadFile(certPath)
	if readErr != nil {
		t.Fatalf("read certificate: %v", readErr)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("generated certificate is not a usable trust anchor")
	}
	return &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}},
	}
}

// A TLS ClientHello passes through untouched: the wrapper must not cost the
// product its HTTPS. This is the clause that makes the other tests meaningful
// — a wrapper that redirected everything would pass them all.
func TestPlaintextRedirectPassesTLSThrough(t *testing.T) {
	addr, client := wrapped(t, httpserver.RedirectOptions{})

	resp := get(t, client, "https://localhost:"+portOf(t, addr)+"/ping")
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	if string(body) != "served" {
		t.Errorf("body = %q; want %q", body, "served")
	}
}

// The case the owner hit: a browser types host:8443 without a scheme, so the
// request arrives as plaintext HTTP. It must land on the https page, not on a
// connection refused, and the redirect must preserve the path, the query and
// the method (308, not 301/302).
func TestPlaintextRedirectAnswers308PreservingTarget(t *testing.T) {
	addr, _ := wrapped(t, httpserver.RedirectOptions{})
	port := portOf(t, addr)

	for _, tc := range []struct {
		name    string
		request string
		want    string
	}{
		{
			name:    "GET with a Host header",
			request: "GET /devices?vlan=200 HTTP/1.1\r\nHost: niac.example.com:" + port + "\r\n\r\n",
			want:    "https://niac.example.com:" + port + "/devices?vlan=200",
		},
		{
			name:    "HEAD with a Host header",
			request: "HEAD / HTTP/1.1\r\nHost: seed.local:" + port + "\r\n\r\n",
			want:    "https://seed.local:" + port + "/",
		},
		{
			name:    "POST is redirected too, which is why this is a 308",
			request: "POST /api/v1/simulation HTTP/1.1\r\nHost: localhost:" + port + "\r\n\r\n",
			want:    "https://localhost:" + port + "/api/v1/simulation",
		},
		{
			name:    "HTTP/1.0 without a Host header falls back to the bound address",
			request: "GET /status HTTP/1.0\r\n\r\n",
			want:    "https://" + addr + "/status",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := plaintextRoundTrip(t, addr, tc.request)

			resp, parseErr := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), nil)
			if parseErr != nil {
				t.Fatalf("parse response %q: %v", response, parseErr)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Errorf("status = %d; want %d", resp.StatusCode, http.StatusPermanentRedirect)
			}
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q; want %q", got, tc.want)
			}
			// http.ReadResponse moves "Connection: close" out of Header and
			// into Close, so this is where the header lands, not Header.Get.
			if !resp.Close {
				t.Error("response does not close the connection; want Connection: close")
			}
		})
	}
}

// The redirect serves nothing but the redirect. A plaintext request must never
// reach the product's handler: these are HTTPS-only products, and a plaintext
// path that returned content would be a downgrade.
func TestPlaintextRedirectServesNoContent(t *testing.T) {
	addr, _ := wrapped(t, httpserver.RedirectOptions{})

	response := plaintextRoundTrip(t, addr, "GET /devices HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if strings.Contains(response, "served") {
		t.Errorf("plaintext request reached the handler: %q", response)
	}
}

// Garbage that is neither TLS nor HTTP gets the connection closed, with no
// response written: a port scanner learns nothing and no goroutine is held.
func TestPlaintextRedirectClosesNonHTTPGarbage(t *testing.T) {
	addr, _ := wrapped(t, httpserver.RedirectOptions{})

	response := plaintextRoundTrip(t, addr, "\x00\x01\x02 not a protocol\r\n\r\n")
	if response != "" {
		t.Errorf("wrote %q to a non-HTTP connection; want nothing", response)
	}
}

// A connection that opens and says nothing must be dropped on the deadline
// rather than holding a goroutine until the process exits (slowloris).
func TestPlaintextRedirectDropsASilentConnection(t *testing.T) {
	addr, _ := wrapped(t, httpserver.RedirectOptions{Timeout: 150 * time.Millisecond})

	conn := dial(t, addr)
	defer func() { _ = conn.Close() }()

	if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatalf("SetDeadline: %v", deadlineErr)
	}
	if _, readErr := io.ReadAll(conn); readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
}

// A plaintext connection must not stall the accept loop for TLS clients: the
// peek happens per connection, not in front of the queue.
func TestPlaintextRedirectDoesNotBlockTLSBehindASilentConnection(t *testing.T) {
	addr, client := wrapped(t, httpserver.RedirectOptions{Timeout: 10 * time.Second})

	silent := dial(t, addr)
	defer func() { _ = silent.Close() }()

	resp := get(t, client, "https://localhost:"+portOf(t, addr)+"/ping")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d; want 200", resp.StatusCode)
	}
}

// dial opens a plain TCP connection. The context-aware forms keep the noctx
// linter satisfied and give every test the same cancellation shape.
func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	var dialer net.Dialer
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return conn
}

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, reqErr := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if reqErr != nil {
		t.Fatalf("new request %s: %v", url, reqErr)
	}
	resp, doErr := client.Do(req)
	if doErr != nil {
		t.Fatalf("GET %s: %v", url, doErr)
	}
	return resp
}
