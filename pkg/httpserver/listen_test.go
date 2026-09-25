// SPDX-License-Identifier: BUSL-1.1

package httpserver_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MustardSeedNetworks/foundation/pkg/httpserver"
)

// serve starts an HTTPS server on the listener cfg produces and returns its
// address and a client that trusts the generated certificate.
func serve(t *testing.T, cfg httpserver.Config) (string, *http.Client) {
	t.Helper()

	ln, err := httpserver.Listen(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "served")
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	pemBytes, readErr := os.ReadFile(filepath.Join(cfg.CertDir, httpserver.DefaultCertFileName))
	if readErr != nil {
		t.Fatalf("read generated certificate: %v", readErr)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		t.Fatal("generated certificate is not a usable trust anchor")
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		},
	}
	return ln.Addr().String(), client
}

// One Listen call gives a product everything the four copies did: a bound
// port, TLS the client can verify against the generated certificate, and the
// plaintext redirect on that same port.
func TestListenServesVerifiableTLSAndRedirectsPlaintext(t *testing.T) {
	dir := t.TempDir()
	addr, client := serve(t, httpserver.Config{
		Addr:    "127.0.0.1:0",
		CertDir: dir,
		Cert:    httpserver.CertOptions{DNSNames: []string{"localhost"}},
	})

	resp := get(t, client, "https://localhost:"+portOf(t, addr)+"/status")
	defer func() { _ = resp.Body.Close() }()
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Fatalf("read body: %v", readErr)
	}
	if string(body) != "served" {
		t.Errorf("body = %q; want %q", body, "served")
	}

	plaintext := plaintextRoundTrip(t, addr, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if !strings.Contains(plaintext, "308") || !strings.Contains(plaintext, "https://localhost/status") {
		t.Errorf("plaintext response = %q; want a 308 to the https URL", plaintext)
	}
}

// ServeTLS advertises h2 itself; Serve on an already-wrapped listener cannot,
// so Listen must. Without it, adopting Listen silently drops every product to
// HTTP/1.1. A client that offers only http/1.1 must still be served.
func TestListenNegotiatesHTTP2AndStillServesHTTP1(t *testing.T) {
	dir := t.TempDir()
	addr, client := serve(t, httpserver.Config{
		Addr:    "127.0.0.1:0",
		CertDir: dir,
		Cert:    httpserver.CertOptions{DNSNames: []string{"localhost"}},
	})
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport is %T; want *http.Transport", client.Transport)
	}
	url := "https://localhost:" + portOf(t, addr) + "/status"

	h2 := &http.Client{Timeout: client.Timeout, Transport: transport.Clone()}
	h2.Transport.(*http.Transport).ForceAttemptHTTP2 = true
	resp := get(t, h2, url)
	_ = resp.Body.Close()
	if resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" || resp.ProtoMajor != 2 {
		t.Errorf("h2-capable client got proto %q; want HTTP/2.0 over ALPN h2", resp.Proto)
	}

	h1 := &http.Client{Timeout: client.Timeout, Transport: transport.Clone()}
	h1.Transport.(*http.Transport).TLSClientConfig.NextProtos = []string{"http/1.1"}
	resp = get(t, h1, url)
	_ = resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.TLS.NegotiatedProtocol != "http/1.1" {
		t.Errorf("http/1.1-only client got proto %q, ALPN %q; want HTTP/1.1", resp.Proto, resp.TLS.NegotiatedProtocol)
	}
}

func portOf(t *testing.T, addr string) string {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	return p
}

// Explicit is the trellis rule, shared: an operator who names a port gets that
// port or an error, never a neighbouring one. A product default still walks.
func TestListenExplicitAddressDoesNotWalk(t *testing.T) {
	held := listenLoopback(t)
	t.Cleanup(func() { _ = held.Close() })

	cfg := httpserver.Config{
		Addr:     held.Addr().String(),
		Explicit: true,
		CertDir:  t.TempDir(),
	}
	ln, err := httpserver.Listen(context.Background(), cfg)
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen bound a neighbouring port for an explicit address")
	}

	cfg.Explicit = false
	cfg.CertDir = t.TempDir()
	walked, walkErr := httpserver.Listen(context.Background(), cfg)
	if walkErr != nil {
		t.Fatalf("Listen with a default address: %v", walkErr)
	}
	t.Cleanup(func() { _ = walked.Close() })
	if walked.Addr().String() == held.Addr().String() {
		t.Error("walked listener reports the held address")
	}
}

// The fleet floor is TLS 1.2 and the default is 1.3. A caller that asks for
// less is refused at start rather than quietly serving a downgrade.
func TestListenRefusesATLSVersionBelowTheFleetFloor(t *testing.T) {
	ln, err := httpserver.Listen(context.Background(), httpserver.Config{
		Addr:       "127.0.0.1:0",
		MinVersion: tls.VersionTLS10,
		CertDir:    t.TempDir(),
	})
	if err == nil {
		_ = ln.Close()
		t.Fatal("Listen accepted TLS 1.0")
	}
	if !strings.Contains(err.Error(), "TLS 1.2") {
		t.Errorf("error %q does not name the floor", err)
	}
}

// An operator's own certificate is used as given; a missing one is a start
// failure naming the path, not a silent fallback to a self-signed pair the
// operator did not ask for.
func TestListenUsesTheOperatorCertificateAndFailsLoudlyWhenItIsMissing(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "operator.crt")
	keyPath := filepath.Join(dir, "operator.key")
	if _, err := httpserver.EnsureCertificate(nil, certPath, keyPath, httpserver.CertOptions{DNSNames: []string{"operator.example"}}); err != nil {
		t.Fatalf("EnsureCertificate: %v", err)
	}

	ln, err := httpserver.Listen(context.Background(), httpserver.Config{
		Addr: "127.0.0.1:0", CertFile: certPath, KeyFile: keyPath,
	})
	if err != nil {
		t.Fatalf("Listen with an operator certificate: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	missing := filepath.Join(dir, "absent.crt")
	_, missingErr := httpserver.Listen(context.Background(), httpserver.Config{
		Addr: "127.0.0.1:0", CertFile: missing, KeyFile: keyPath,
	})
	if missingErr == nil {
		t.Fatal("Listen accepted a missing operator certificate")
	}
	if !strings.Contains(missingErr.Error(), missing) {
		t.Errorf("error %q does not name the missing certificate", missingErr)
	}
}

// The products get the certificate log line through Listen, not by calling
// EnsureCertificate; without Config.Logger reaching it the fix in
// foundation#76 would never show up in a product's journal.
func TestListenLogsTheCertificateItGenerates(t *testing.T) {
	var buf bytes.Buffer
	serve(t, httpserver.Config{
		Addr:    "127.0.0.1:0",
		CertDir: t.TempDir(),
		Logger:  slog.New(slog.NewJSONHandler(&buf, nil)),
	})

	if !strings.Contains(buf.String(), `"msg":"generated self-signed TLS certificate"`) {
		t.Errorf("Listen did not log the generated certificate; log: %s", buf.String())
	}
}
