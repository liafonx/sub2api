package tlsfingerprint

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// DialTLSContextFunc is the function signature for TLS dialers.
// Matches http.Transport.DialTLSContext.
type DialTLSContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// H1TransportSettings contains connection pool settings for the HTTP/1.1 fallback transport.
// HTTP/2 transport manages its own connection via multiplexing.
type H1TransportSettings struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	ResponseHeaderTimeout time.Duration
}

// protocolConn is optionally implemented by connections that expose
// the ALPN-negotiated protocol. Allows testing without a real utls connection.
type protocolConn interface {
	NegotiatedProtocol() string
}

// h2RoundTripper detects the ALPN-negotiated protocol on the first connection
// to each host, creates the appropriate transport (http2.Transport or http.Transport),
// and caches it for subsequent requests to that host.
type h2RoundTripper struct {
	mu         sync.Mutex
	dialTLS    DialTLSContextFunc
	transports map[string]http.RoundTripper // host:port → cached transport
	h1Settings H1TransportSettings
}

// NewH2RoundTripper creates a protocol-detecting RoundTripper.
// dialTLS must return a connection with ALPN negotiated (typically *utls.UConn).
func NewH2RoundTripper(dialTLS DialTLSContextFunc, settings H1TransportSettings) http.RoundTripper {
	return &h2RoundTripper{
		dialTLS:    dialTLS,
		transports: make(map[string]http.RoundTripper),
		h1Settings: settings,
	}
}

// RoundTrip implements http.RoundTripper. On the first request to a host it
// probes the ALPN protocol and creates the appropriate transport. Subsequent
// requests reuse the cached transport.
func (rt *h2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := hostAddr(req)

	rt.mu.Lock()
	if t, ok := rt.transports[addr]; ok {
		rt.mu.Unlock()
		return t.RoundTrip(req)
	}

	// Probe: dial to detect ALPN-negotiated protocol.
	// The mutex is held to prevent duplicate probes for the same host.
	conn, err := rt.dialTLS(req.Context(), "tcp", addr)
	if err != nil {
		rt.mu.Unlock()
		return nil, err
	}

	proto := getNegotiatedProtocol(conn)
	var transport http.RoundTripper

	if proto == "h2" {
		// Pass the bootstrap connection to the HTTP/2 transport via onceConn
		// so the already-completed TLS handshake is not wasted.
		once := &onceConn{conn: conn}
		h2t := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				if c := once.take(); c != nil {
					return c, nil
				}
				return rt.dialTLS(ctx, network, addr)
			},
		}
		transport = h2t
		slog.Debug("h2_transport_created", "host", addr)
	} else {
		// HTTP/1.1 fallback: close probe connection; transport manages its own pool.
		_ = conn.Close()
		transport = &http.Transport{
			DialTLSContext:        rt.dialTLS,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          rt.h1Settings.MaxIdleConns,
			MaxIdleConnsPerHost:   rt.h1Settings.MaxIdleConnsPerHost,
			MaxConnsPerHost:       rt.h1Settings.MaxConnsPerHost,
			IdleConnTimeout:       rt.h1Settings.IdleConnTimeout,
			ResponseHeaderTimeout: rt.h1Settings.ResponseHeaderTimeout,
		}
		slog.Debug("h1_transport_created", "host", addr)
	}

	rt.transports[addr] = transport
	rt.mu.Unlock()

	return transport.RoundTrip(req)
}

// onceConn wraps a net.Conn and returns it exactly once via take().
// After the first take(), all subsequent calls return nil.
type onceConn struct {
	mu   sync.Mutex
	conn net.Conn
}

func (o *onceConn) take() net.Conn {
	o.mu.Lock()
	defer o.mu.Unlock()
	c := o.conn
	o.conn = nil
	return c
}

// getNegotiatedProtocol extracts the ALPN protocol from a connection.
// First checks the protocolConn interface (for testability), then falls
// back to *utls.UConn type assertion for production use.
// Returns "" if the connection type is not recognized.
func getNegotiatedProtocol(conn net.Conn) string {
	if pc, ok := conn.(protocolConn); ok {
		return pc.NegotiatedProtocol()
	}
	if uConn, ok := conn.(*utls.UConn); ok {
		return uConn.ConnectionState().NegotiatedProtocol
	}
	return ""
}

// hostAddr returns the canonical host:port string used as the transport cache key.
// If the request URL has no explicit port, adds ":443" (default HTTPS port).
func hostAddr(req *http.Request) string {
	if req.URL.Port() != "" {
		return req.URL.Host
	}
	return net.JoinHostPort(req.URL.Hostname(), "443")
}
