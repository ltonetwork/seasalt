package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.nio.charset.StandardCharsets;

public class SHA3384 {

    private static SHA3Digest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new SHA3Digest(384);
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
