package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.nio.charset.StandardCharsets;

public class SHA3 {

    private static SHA3Digest SHA3256Digest;
    private static SHA3Digest SHA3384Digest;
    private static SHA3Digest SHA3512Digest;

    public static Binary SHA3256Hash(byte[] value) {
        if(SHA3256Digest == null) SHA3256Digest = new SHA3Digest(256);
        return SHA3Hash(value, SHA3256Digest);
    }

    public static Binary SHA3256Hash(String value) {
        return SHA3256Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary SHA3384Hash(byte[] value) {
        if(SHA3384Digest == null) SHA3384Digest = new SHA3Digest(384);
        return SHA3Hash(value, SHA3384Digest);
    }

    public static Binary SHA3384Hash(String value) {
        return SHA3384Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary SHA3512Hash(byte[] value) {
        if(SHA3512Digest == null) SHA3512Digest = new SHA3Digest(512);
        return SHA3Hash(value, SHA3512Digest);
    }

    public static Binary SHA3512Hash(String value) {
        return SHA3512Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    private static Binary SHA3Hash (byte[] value, SHA3Digest digest) {
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }
}
