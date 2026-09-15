package io.ciphertun.cdm

import java.util.Locale

/** Protocol intelligence is independent from the application name. A config can carry many protocols at once. */
object ProtocolDetector {
    fun detect(text: String, fields: List<Pair<String, String>> = emptyList()): List<String> {
        val s = (text + "\n" + fields.joinToString("\n") { "${it.first}: ${it.second}" }).lowercase(Locale.ROOT)
        val out = linkedSetOf<String>()
        fun has(vararg x: String) = x.any { s.contains(it) }

        if (has("vless", "vless://")) out += "VLESS"
        if (has("vmess", "vmess://")) out += "VMess"
        if (has("trojan", "trojan://")) out += "Trojan"
        if (has("shadowsocks", "ss://", "shadowsocks://")) out += "Shadowsocks"
        if (has("socks5", "socks5://", "socks://")) out += "SOCKS"
        if (has("http proxy", "http://", "https://", "http/1.1", "http/2")) out += "HTTP/HTTPS"
        if (has("ssh", "ssh2.0", "openssh")) out += "SSH"
        if (has("openvpn", "dev tun", "client")) out += "OpenVPN"
        if (has("wireguard", "[interface]", "[peer]")) out += "WireGuard"
        if (has("reality", "reality-public-key", "shortid")) out += "Reality"
        if (has("hysteria2", "hysteria2://", "hysteria")) out += "Hysteria / Hysteria2"
        if (has("tuic", "tuic://")) out += "TUIC"
        if (has("naiveproxy", "naive+https", "naiveproxy")) out += "NaiveProxy"
        if (has("mtproto", "tg://proxy", "telegram proxy")) out += "MTProto"
        if (has("quic", "http3", "h3")) out += "QUIC / HTTP/3"
        if (has("websocket", "ws://", "ws+tls", "ws path", "path")) out += "WebSocket"
        if (has("grpc", "grpc-service-name")) out += "gRPC"
        if (has("tcp")) out += "TCP"
        if (has("udp")) out += "UDP"
        if (has("icmp")) out += "ICMP"
        if (has("dns tunnel", "dnstt", "dns://")) out += "DNS tunneling"
        if (has("tls", "ssl", "server name", "sni")) out += "TLS"
        if (has("http payload", "[crlf]", "connect [host_port]")) out += "HTTP injection / custom payload"
        return out.toList()
    }
}
