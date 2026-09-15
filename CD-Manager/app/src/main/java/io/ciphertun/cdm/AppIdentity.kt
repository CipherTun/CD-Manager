package io.ciphertun.cdm

import java.util.Locale

/** Semantic application identification. Extension is only one signal; content signatures can override it. */
data class AppIdentity(
    val appName: String,
    val formatName: String,
    val extension: String,
    val confidence: Int,
    val evidence: List<String>,
    val status: String
)

object AppIdentityEngine {
    fun identify(name: String, bytes: ByteArray, ext: String): AppIdentity {
        val lower = bytes.toString(Charsets.ISO_8859_1).lowercase(Locale.ROOT)
        val e = ext.lowercase(Locale.ROOT)

        val signatures = listOf(
            Rule("Dark Tunnel", "Dark Tunnel configuration", setOf("dark"), listOf("darktunnel://", "encryptedlockedconfig")),
            Rule("Stark VPN", "Stark VPN configuration", setOf("stk"), listOf("starkvpn", "stark vpn", "starkvpnconfig")),
            Rule("HA Tunnel Plus", "HA Tunnel Plus configuration", setOf("hat"), listOf("hatunnel", "ha tunnel plus", "hat+")),
            Rule("HTTP Injector", "HTTP Injector configuration", setOf("ehi"), listOf("http injector", "ehi")),
            Rule("HTTP Injector Lite", "HTTP Injector Lite configuration", setOf("ehil"), listOf("http injector lite", "ehil")),
            Rule("HTTP Custom", "HTTP Custom configuration", setOf("hc"), listOf("httpcustom", "http custom", "hctools")),
            Rule("ZIVPN", "ZIVPN configuration", setOf("ziv"), listOf("zivpn", "zivpn.com")),
            Rule("KPN Tunnel Revolution", "KPN Tunnel Revolution configuration", setOf("ktr"), listOf("kpn tunnel", "kpn-tunnel", "ktr")),
            Rule("Maya VPN", "Maya VPN configuration", setOf("maya"), listOf("maya vpn", "maya_vpn")),
            Rule("NapsternetV", "NapsternetV configuration", setOf("npv4", "npvt"), listOf("napsternetv", "npvt")),
            Rule("OpenTunnel", "OpenTunnel configuration", setOf("tnl"), listOf("opentunnel")),
            Rule("SocksIP Tunnel", "SocksIP Tunnel configuration", setOf("sip"), listOf("socksip")),
            Rule("NetMod", "NetMod configuration", setOf("nm"), listOf("netmod")),
            Rule("TLS Tunnel", "TLS Tunnel configuration", setOf("tls"), listOf("tls tunnel")),
            Rule("SSH configuration", "OpenSSH / SSH configuration", setOf("ssh"), listOf("openssh", "ssh_config", "host ")),
            Rule("OpenVPN", "OpenVPN configuration", setOf("ovpn"), listOf("client", "dev tun", "remote ", "proto ")),
            Rule("WireGuard", "WireGuard configuration", setOf("wg", "wireguard"), listOf("[interface]", "[peer]", "privatekey", "publickey"))
        )

        val strong = signatures.firstOrNull { rule -> rule.signatures.any { lower.contains(it) } }
        if (strong != null) return AppIdentity(strong.app, strong.format, ".${e.ifEmpty { "unknown" }}", 99, listOf("Internal content signature: ${strong.signatures.first { lower.contains(it) }}"), "Content identified")

        val extRule = signatures.firstOrNull { e in it.extensions }
        if (extRule != null) return AppIdentity(extRule.app, extRule.format, ".${e}", 90, listOf("Known application extension"), "Extension identified; content verification unavailable")

        return AppIdentity("Unknown application", "Unknown / generic file", if (e.isEmpty()) "none" else ".${e}", 20, listOf("No trusted application signature matched"), "Unsupported / unidentified")
    }

    private data class Rule(val app: String, val format: String, val extensions: Set<String>, val signatures: List<String>)
}
