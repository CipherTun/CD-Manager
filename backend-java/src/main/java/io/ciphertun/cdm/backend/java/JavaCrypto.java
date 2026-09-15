package io.ciphertun.cdm.backend.java;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

public final class JavaCrypto {
    private JavaCrypto() {}
    public static String sha256(byte[] data) throws Exception { return digest("SHA-256", data); }
    public static String sha1(byte[] data) throws Exception { return digest("SHA-1", data); }
    public static String md5(byte[] data) throws Exception { return digest("MD5", data); }
    public static byte[] randomBytes(int length) {
        if (length < 0) throw new IllegalArgumentException("length < 0");
        byte[] out = new byte[length]; new SecureRandom().nextBytes(out); return out;
    }
    private static String digest(String algorithm, byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance(algorithm).digest(data));
    }
}
