package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA3Digest;

import java.nio.charset.StandardCharsets;

public class SHA3256 extends Hasher {

    private static SHA3Digest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new SHA3Digest(256);
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
