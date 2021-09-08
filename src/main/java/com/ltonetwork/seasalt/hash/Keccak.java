package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.KeccakDigest;

import java.nio.charset.StandardCharsets;

public class Keccak {

    private static KeccakDigest keccak256Digest;
    private static KeccakDigest keccak384Digest;
    private static KeccakDigest keccak512Digest;

    public static Binary keccak256Hash(byte[] value) {
        if(keccak256Digest == null) keccak256Digest = new KeccakDigest(256);
        return keccakHash(value, keccak256Digest);
    }

    public static Binary keccak256Hash(String value) {
        return keccak256Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary keccak384Hash(byte[] value) {
        if(keccak384Digest == null) keccak384Digest = new KeccakDigest(384);
        return keccakHash(value, keccak384Digest);
    }

    public static Binary keccak384Hash(String value) {
        return keccak384Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary keccak512Hash(byte[] value) {
        if(keccak512Digest == null) keccak512Digest = new KeccakDigest(512);
        return keccakHash(value, keccak512Digest);
    }

    public static Binary keccak512Hash(String value) {
        return keccak512Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    private static Binary keccakHash (byte[] value, KeccakDigest digest) {
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }
}
