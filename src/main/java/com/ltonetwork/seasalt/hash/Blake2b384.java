package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.nio.charset.StandardCharsets;

public class Blake2b384 extends Hasher {

    private static Blake2bDigest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new Blake2bDigest(384);
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
