package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.nio.charset.StandardCharsets;

public class SHA1 {

    private static SHA1Digest SHA1Digest;

    public static Binary hash(byte[] value) {
        if(SHA1Digest == null) SHA1Digest = new SHA1Digest();
        byte[] rawHash = new byte[SHA1Digest.getDigestSize()];
        SHA1Digest.update(value, 0, value.length);
        SHA1Digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
