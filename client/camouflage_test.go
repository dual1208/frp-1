package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/websocket"
)

func TestCamouflageSingleTLSAndPersistentWebSocket(t *testing.T) {
	secret := strings.Repeat("a", 43)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Camouflage-Secret") != secret || r.URL.Path != "/~!frp" {
			t.Error("missing transport credential or incorrect path")
			w.WriteHeader(403)
			return
		}
		websocket.Handler(func(ws *websocket.Conn) {
			defer ws.Close()
			ws.PayloadType = websocket.BinaryFrame
			_, _ = io.Copy(ws, ws)
		}).ServeHTTP(w, r)
	}))
	defer server.Close()
	d := t.TempDir()
	secretFile := filepath.Join(d, "secret")
	require.NoError(t, os.WriteFile(secretFile, []byte(secret+"\n"), 0600))
	caFile := filepath.Join(d, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	cfg := &v1.ClientCommonConfig{ServerAddr: host, ServerPort: n}
	require.NoError(t, cfg.Complete())
	cfg.Transport.Protocol = "camouflage"
	cfg.Transport.Camouflage = &v1.CamouflageClientConfig{SecretFile: secretFile}
	cfg.Transport.TLS.TrustedCaFile = caFile
	cfg.Transport.DialServerTimeout = 1
	connector := &defaultConnectorImpl{ctx: context.Background(), cfg: cfg}
	conn, err := connector.realConnect()
	require.NoError(t, err)
	defer conn.Close()
	// A second TLS handshake here would reach the WebSocket application instead
	// of this exact payload. Also ensure the setup deadline was removed.
	time.Sleep(1100 * time.Millisecond)
	payload := []byte{0, 255, 254, 1, 0, 42}
	_, err = conn.Write(payload)
	require.NoError(t, err)
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)
	cfg.Transport.TLS.TrustedCaFile = ""
	public, _, err := camouflageOptions(cfg)
	require.NoError(t, err)
	require.False(t, public.InsecureSkipVerify)
	require.Nil(t, public.RootCAs)
	require.Equal(t, host, public.ServerName)
}

func TestCamouflageHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	raw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer raw.Close()
	peer := <-accepted
	defer peer.Close()
	start := time.Now()
	_, _, err = camouflageDialHook(&tls.Config{RootCAs: x509.NewCertPool(), ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, nil, 100*time.Millisecond)(context.Background(), raw, listener.Addr().String())
	require.Error(t, err)
	require.Less(t, time.Since(start), time.Second)
}
