package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA1Digest;

import java.nio.charset.StandardCharsets;

public class SHA1 extends Hasher {

    private static SHA1Digest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new SHA1Digest();
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary hash(Binary value) {
        return hash(value.getBytes());
    }
}
