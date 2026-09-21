package net

import (
	"context"
	"net"
	"net/http"
	"net/url"

	libnet "github.com/fatedier/golib/net"
	"golang.org/x/net/websocket"
)

func DialHookCustomTLSHeadByte(enableTLS bool, disableCustomTLSHeadByte bool) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if enableTLS && !disableCustomTLSHeadByte {
			_, err := c.Write([]byte{byte(FRPTLSHeadByte)})
			if err != nil {
				return nil, nil, err
			}
		}
		return ctx, c, nil
	}
}

func DialHookWebsocket(protocol string, host string) libnet.AfterHookFunc {
	return DialHookWebsocketWithHeaders(protocol, host, nil)
}

// DialHookWebsocketWithHeaders adds transport headers without changing proxy HTTP headers.
func DialHookWebsocketWithHeaders(protocol string, host string, headers http.Header) libnet.AfterHookFunc {
	return func(ctx context.Context, c net.Conn, addr string) (context.Context, net.Conn, error) {
		if protocol != "wss" {
			protocol = "ws"
		}
		if host == "" {
			host = addr
		}
		addr = protocol + "://" + host + FrpWebsocketPath
		uri, err := url.Parse(addr)
		if err != nil {
			return nil, nil, err
		}

		origin := "http://" + uri.Host
		cfg, err := websocket.NewConfig(addr, origin)
		if err != nil {
			return nil, nil, err
		}

		cfg.Header = headers.Clone()
		conn, err := websocket.NewClient(cfg, c)
		if err != nil {
			return nil, nil, err
		}
		// The tunnel payload is a raw byte stream (yamux), not UTF-8 text.
		// Send it as binary frames; otherwise RFC 6455-compliant intermediaries
		// (e.g. API gateways/reverse proxies) UTF-8-validate the default text
		// frames and close the connection on invalid bytes.
		conn.PayloadType = websocket.BinaryFrame
		return ctx, conn, nil
	}
}
