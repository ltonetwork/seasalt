package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.nio.charset.StandardCharsets;

public class Blake2b512 extends Hasher {

    private static Blake2bDigest digest;

    public synchronized static Binary hash(byte[] value) {
        if(digest == null) digest = new Blake2bDigest(512);
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary hash(Binary value) {
        return hash(value.getBytes());
    }
}
