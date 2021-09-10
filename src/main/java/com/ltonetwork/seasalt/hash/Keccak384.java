package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.KeccakDigest;

import java.nio.charset.StandardCharsets;

public class Keccak384 extends Hasher {

    private static KeccakDigest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new KeccakDigest(384);
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary hash(Binary value) {
        return hash(value.getBytes());
    }
}
