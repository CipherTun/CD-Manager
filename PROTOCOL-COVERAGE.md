# CD Manager protocol coverage

CD Manager is protocol-neutral. It does not assume that every VPN configuration is V2Ray/Xray.

## Families recognized by the intelligence layer

- SSH / SSH2
- HTTP / HTTPS
- HTTP custom payload / injection
- SOCKS4 / SOCKS5
- TCP / UDP / ICMP
- TLS / SNI
- WebSocket
- gRPC
- QUIC / HTTP/3
- OpenVPN
- WireGuard
- VLESS
- VMess
- Trojan
- Shadowsocks
- Reality
- Hysteria / Hysteria2
- TUIC
- NaiveProxy
- MTProto
- DNS tunneling / DNS transport

## Important distinction

Detection is not the same as decryption or execution.

If a file contains a recognizable protocol but its application-specific container is unknown, CD Manager reports the protocol and leaves the protected fields untouched.

If an application-specific adapter successfully decrypts a configuration, the common result model exposes human-readable values such as:

- Application
- Configuration name
- Protocol
- Transport
- Server / host
- Port
- SNI / server name
- Proxy
- Payload / injection
- DNS
- TLS settings
- Authentication mode
- Username
- Password/token (shown in full when recovered)
- Keys / UUID / identifiers (shown in full when recovered)
- Routing / mux / flow where present

Raw Format is a separate action so the normal screen remains readable.
