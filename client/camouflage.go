// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0.
// See LICENSE for the full license text.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	libnet "github.com/fatedier/golib/net"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

func camouflageOptions(cfg *v1.ClientCommonConfig) (*tls.Config, http.Header, error) {
	c := cfg.Transport.Camouflage
	if c == nil || c.SecretFile == "" {
		return nil, nil, fmt.Errorf("camouflage secret file is required")
	}
	if cfg.Transport.TLS.Enable == nil || !*cfg.Transport.TLS.Enable {
		return nil, nil, fmt.Errorf("camouflage requires public TLS")
	}
	f, err := os.Open(c.SecretFile)
	if err != nil {
		return nil, nil, fmt.Errorf("open camouflage secret file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, nil, fmt.Errorf("camouflage secret must be a regular file readable only by its owner")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil {
		return nil, nil, err
	}
	secret := strings.TrimSpace(string(b))
	if len(b) > 1024 || len(secret) < 32 || len(secret) > 256 {
		return nil, nil, fmt.Errorf("camouflage secret must contain 32 to 256 URL-safe characters")
	}
	for _, c := range secret {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, nil, fmt.Errorf("camouflage secret contains an invalid character")
		}
	}
	name := cfg.Transport.TLS.ServerName
	if name == "" {
		name = cfg.ServerAddr
	}
	outer := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	if cfg.Transport.TLS.TrustedCaFile != "" {
		pem, err := os.ReadFile(cfg.Transport.TLS.TrustedCaFile)
		if err != nil {
			return nil, nil, fmt.Errorf("read camouflage CA file: %w", err)
		}
		outer.RootCAs = x509.NewCertPool()
		if !outer.RootCAs.AppendCertsFromPEM(pem) {
			return nil, nil, fmt.Errorf("camouflage CA file contains no certificates")
		}
	}
	return outer, http.Header{"X-Camouflage-Secret": []string{secret}}, nil
}

// camouflageDialHook completes the only TLS handshake and WebSocket upgrade
// within the configured dial timeout, then removes the deadline for FRP traffic.
func camouflageDialHook(config *tls.Config, headers http.Header, timeout time.Duration) libnet.AfterHookFunc {
	return func(ctx context.Context, raw net.Conn, addr string) (context.Context, net.Conn, error) {
		deadline := time.Now().Add(timeout)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := raw.SetDeadline(deadline); err != nil {
			return ctx, nil, err
		}
		conn := tls.Client(raw, config)
		if err := conn.HandshakeContext(ctx); err != nil {
			return ctx, nil, err
		}
		nextCtx, ws, err := netpkg.DialHookWebsocketWithHeaders("wss", "", headers)(ctx, conn, addr)
		if err != nil {
			return ctx, nil, err
		}
		if err := ws.SetDeadline(time.Time{}); err != nil {
			return ctx, nil, err
		}
		return nextCtx, ws, nil
	}
}
