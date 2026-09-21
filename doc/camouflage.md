# HTTPS camouflage transport

This fork adds `transport.protocol = "camouflage"` for a Rust HTTPS frontend.
It uses **one verified TLS connection**, ending at that frontend. FRP messages
travel inside its WebSocket connection. The frontend forwards decrypted bytes
over loopback to frps; frps still verifies the FRP token.

```toml
serverAddr = "8.163.2.191"
serverPort = 44915
transport.protocol = "camouflage"
transport.camouflage.secretFile = "/private/path/camouflage.secret"
transport.tls.enable = true
transport.tls.serverName = "8.163.2.191"
# Omit trustedCaFile to verify against system certificate authorities.
# Do not configure client certFile or keyFile for this transport.
```

Keep the existing FRP token and proxy/visitor settings. The secret file must be
owner-only and contain 32–256 random URL-safe characters, with an optional newline.
Generate it once, keep it out of Git, and copy it to the frontend and clients.
Errors never include its contents. It goes in `X-Camouflage-Secret` during the
WebSocket handshake, never in a URL or an application proxy's headers.

The frontend must serve ordinary website responses unless this header and the
WebSocket handshake are valid. It must strip the credential before connecting
to its fixed private upstream. Configure frps with `bindAddr = "127.0.0.1"`, a
separate unused port and `transport.tls.force = false`; remove the former transport
CA, certificate and key settings. Do not expose the plaintext frps listener.

The dial timeout covers TLS and WebSocket setup. After setup there is no added
connection deadline; FRP handles heartbeats and reconnection. A frontend restart
disconnects active tunnels. Certificate verification is required even when no
custom CA file is provided. Other transport modes keep their existing behavior.
