package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.nio.charset.StandardCharsets;

public class SHA512 {

    private static SHA512Digest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new SHA512Digest();
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
