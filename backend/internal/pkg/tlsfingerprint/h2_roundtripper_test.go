//go:build unit

package tlsfingerprint

import (
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProtoConn implements net.Conn and protocolConn for testing.
// The NegotiatedProtocol field controls what ALPN protocol is reported.
type mockProtoConn struct {
	proto  string
	closed bool
	mu     sync.Mutex
}

func (m *mockProtoConn) Read(b []byte) (int, error)         { return 0, nil }
func (m *mockProtoConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockProtoConn) Close() error                       { m.mu.Lock(); defer m.mu.Unlock(); m.closed = true; return nil }
func (m *mockProtoConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockProtoConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockProtoConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockProtoConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockProtoConn) SetWriteDeadline(_ time.Time) error { return nil }
func (m *mockProtoConn) NegotiatedProtocol() string         { return m.proto }

// plainConn implements net.Conn only — no protocolConn interface.
type plainConn struct{}

func (p *plainConn) Read(b []byte) (int, error)         { return 0, nil }
func (p *plainConn) Write(b []byte) (int, error)        { return len(b), nil }
func (p *plainConn) Close() error                       { return nil }
func (p *plainConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (p *plainConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (p *plainConn) SetDeadline(_ time.Time) error      { return nil }
func (p *plainConn) SetReadDeadline(_ time.Time) error  { return nil }
func (p *plainConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestOnceConnTake verifies the connection is returned on the first take and nil after.
func TestOnceConnTake(t *testing.T) {
	conn := &mockProtoConn{}
	once := &onceConn{conn: conn}

	got1 := once.take()
	assert.NotNil(t, got1, "first take should return the connection")
	assert.Equal(t, conn, got1)

	got2 := once.take()
	assert.Nil(t, got2, "second take should return nil")
}

// TestOnceConnConcurrent verifies exactly one goroutine receives the connection.
func TestOnceConnConcurrent(t *testing.T) {
	conn := &mockProtoConn{}
	once := &onceConn{conn: conn}

	const n = 50
	results := make([]net.Conn, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			results[i] = once.take()
		}()
	}
	wg.Wait()

	nonNil := 0
	for _, r := range results {
		if r != nil {
			nonNil++
		}
	}
	assert.Equal(t, 1, nonNil, "exactly one goroutine should receive the connection")
}

// TestGetNegotiatedProtocol verifies protocol extraction from various connection types.
func TestGetNegotiatedProtocol(t *testing.T) {
	tests := []struct {
		name string
		conn net.Conn
		want string
	}{
		{"h2 via protocolConn", &mockProtoConn{proto: "h2"}, "h2"},
		{"http/1.1 via protocolConn", &mockProtoConn{proto: "http/1.1"}, "http/1.1"},
		{"empty proto via protocolConn", &mockProtoConn{proto: ""}, ""},
		{"plain conn without interface", &plainConn{}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getNegotiatedProtocol(tc.conn)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestHostAddr verifies canonical host:port construction from request URLs.
func TestHostAddr(t *testing.T) {
	tests := []struct {
		name string
		rawURL string
		want string
	}{
		{
			name:   "no port adds :443",
			rawURL: "https://api.anthropic.com/v1/messages",
			want:   "api.anthropic.com:443",
		},
		{
			name:   "explicit port preserved",
			rawURL: "https://api.anthropic.com:8443/v1",
			want:   "api.anthropic.com:8443",
		},
		{
			name:   "ipv4 without port adds :443",
			rawURL: "https://1.2.3.4/path",
			want:   "1.2.3.4:443",
		},
		{
			name:   "ipv4 with explicit port preserved",
			rawURL: "https://1.2.3.4:9000/path",
			want:   "1.2.3.4:9000",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			require.NoError(t, err)
			req := &http.Request{URL: u}
			got := hostAddr(req)
			assert.Equal(t, tc.want, got)
		})
	}
}
