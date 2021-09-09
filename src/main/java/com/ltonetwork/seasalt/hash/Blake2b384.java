package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.nio.charset.StandardCharsets;

public class Blake2b384 {

    private static Blake2bDigest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new Blake2bDigest(384);
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
