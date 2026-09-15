package io.ciphertun.cdm.backend.protocol

import java.util.Locale

object ProtocolBackend {
    const val NAME = "Protocol Intelligence Backend"
    fun available() = true
    fun detect(text: String): List<String> {
        val s = text.lowercase(Locale.ROOT)
        val out = linkedSetOf<String>()
        fun hit(vararg needles: String) = needles.any { s.contains(it) }
        if (hit("ssh://", "ssh2", "openssh", "dropbear")) out += "SSH/SSH2"
        if (hit("http://", "https://", "host:", "user-agent:", "http/1.1")) out += "HTTP/HTTPS"
        if (hit("socks5", "socks://", "socks4")) out += "SOCKS"
        if (hit("vless://", "vless")) out += "VLESS"
        if (hit("vmess://", "vmess")) out += "VMess"
        if (hit("trojan://", "trojan")) out += "Trojan"
        if (hit("ss://", "shadowsocks")) out += "Shadowsocks"
        if (hit("wireguard", "wg-quick", "privatekey", "publickey")) out += "WireGuard"
        if (hit("openvpn", "client\n", "remote ")) out += "OpenVPN"
        if (hit("websocket", "ws://", "wss://", "sec-websocket")) out += "WebSocket"
        if (hit("grpc", "grpc-service-name")) out += "gRPC"
        if (hit("quic", "http/3", "h3")) out += "QUIC/HTTP3"
        if (hit("reality", "shortid", "publickey")) out += "Reality"
        if (hit("hysteria2", "hysteria")) out += "Hysteria/Hysteria2"
        if (hit("tuic")) out += "TUIC"
        if (hit("naiveproxy", "naive")) out += "NaiveProxy"
        if (hit("mtproto", "telegram")) out += "MTProto"
        if (hit("dns tunnel", "dnstt", "iodine", "dns://")) out += "DNS tunneling"
        if (hit("payload", "inject", "http custom", "http injector")) out += "Custom HTTP injection/payload"
        if (hit("sni", "server_name", "servername")) out += "TLS/SNI"
        if (hit("tcp")) out += "TCP"
        if (hit("udp")) out += "UDP"
        if (hit("icmp")) out += "ICMP"
        return out.toList()
    }
}
