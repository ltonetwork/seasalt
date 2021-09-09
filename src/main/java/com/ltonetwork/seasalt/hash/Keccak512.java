package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.KeccakDigest;

import java.nio.charset.StandardCharsets;

public class Keccak512 {

    private static KeccakDigest digest;

    public static Binary hash(byte[] value) {
        if(digest == null) digest = new KeccakDigest(512);
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
