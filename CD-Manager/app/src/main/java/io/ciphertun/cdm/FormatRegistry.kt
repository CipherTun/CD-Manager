package io.ciphertun.cdm

object FormatRegistry {
    private val vpnNames = listOf(
        "dark" to "Dark Tunnel", "ehi" to "HTTP Injector", "ehil" to "HTTP Injector Lite",
        "hat" to "HA Tunnel Plus", "hc" to "HTTP Custom", "ziv" to "ZIVPN", "ktr" to "KPN Tunnel Revolution",
        "maya" to "Maya VPN", "jz" to "JZ / tunnel candidate", "v2" to "EV2Ray", "pcx" to "PCX / Snake Tunnel",
        "sip" to "SocksIP Tunnel", "agn" to "AGN Injector", "aro" to "Austro VPN", "stk" to "Stark VPN",
        "hex" to "Hex VPN", "sbr" to "SBR Injector", "ssc" to "SSH Custom", "vhd" to "V2Ray Hybrid",
        "ssh" to "SSH config", "rez" to "Rez Tunnel", "tnl" to "OpenTunnel", "ost" to "Ouss Tunnel",
        "tls" to "TLS Tunnel", "sut" to "SMK Tun Plus", "npv4" to "NapsternetV", "npvt" to "NPV Tunnel",
        "ink" to "Link Layer", "pin" to "Poy Injector", "roy" to "Royal Tunnel", "jez" to "Jez Proxy",
        "nm" to "NetMod", "mina" to "Mina", "slipnet" to "SlipNet", "jvc" to "JVC", "jvi" to "JVI",
        "phc" to "PHC", "mrc" to "MRC", "cly" to "CLY", "uwu" to "UWU", "aura" to "Aura VPN",
        "bcl" to "BCL", "bee" to "Bee VPN", "btv" to "BTV", "eta" to "ETA", "fix" to "Fix VPN",
        "glory" to "Glory", "marvs" to "Marvs", "nur" to "Nur", "mdvpn" to "MDVPN", "md" to "MD VPN",
        "osv" to "OSV", "ry" to "RY", "t20" to "T20", "tik" to "Tik VPN", "tsm" to "TSM", "tx" to "TX",
        "ulti" to "Ulti", "ultra" to "Ultra", "vlx" to "VLX", "wolf" to "Wolf", "mmt" to "MMT",
        "tcx" to "TCX", "7net" to "7Net", "ihome" to "iHome", "xhypher" to "Xhypher", "izph" to "IZPH",
        "osp" to "OSP", "bshield" to "BShield", "apnalite" to "APNA Lite", "bdnet" to "BDNet",
        "hxt" to "HXT", "4ulite" to "4U Lite", "fnf" to "FNF"
    )

    val all: List<FormatSpec> = vpnNames.map {
        val status = when (it.first) {
            "dark" -> "Implemented parser + decryption"
            "hc" -> "Implemented version-aware adapter; key/version dependent"
            else -> "Detected / universal decoding + structure analysis"
        }
        FormatSpec(it.first, it.second, "VPN / tunnel", status)
    } + listOf(
        FormatSpec("zip", "ZIP", "archive", "read/extract"), FormatSpec("7z", "7-Zip", "archive", "read/extract"),
        FormatSpec("tar", "TAR", "archive", "read/extract"), FormatSpec("gz", "GZIP", "compression", "read"),
        FormatSpec("bz2", "BZIP2", "compression", "read"), FormatSpec("xz", "XZ", "compression", "read"),
        FormatSpec("zst", "Zstandard", "compression", "read"), FormatSpec("rar", "RAR", "archive", "detection"),
        FormatSpec("pdf", "PDF", "document", "signature"), FormatSpec("apk", "Android APK", "package", "signature"),
        FormatSpec("aab", "Android App Bundle", "package", "signature"), FormatSpec("dex", "DEX", "Android binary", "signature"),
        FormatSpec("json", "JSON", "text", "parser"), FormatSpec("xml", "XML", "text", "parser"),
        FormatSpec("txt", "Text", "text", "parser"), FormatSpec("csv", "CSV", "text", "parser"),
        FormatSpec("conf", "Network config", "config", "parser"), FormatSpec("ovpn", "OpenVPN", "VPN", "parser"),
        FormatSpec("wireguard", "WireGuard", "VPN", "parser"), FormatSpec("wg", "WireGuard", "VPN", "parser"),
        FormatSpec("pem", "PEM certificate/key", "security", "parser"), FormatSpec("crt", "Certificate", "security", "parser"),
        FormatSpec("cer", "Certificate", "security", "parser"), FormatSpec("der", "DER certificate", "security", "signature"),
        FormatSpec("sqlite", "SQLite database", "database", "signature"), FormatSpec("db", "Database candidate", "database", "generic")
    )

    fun lookup(ext: String): FormatSpec? = all.firstOrNull { it.extension.equals(ext, true) }
}
