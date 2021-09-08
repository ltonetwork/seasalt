package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.Blake2bDigest;

import java.nio.charset.StandardCharsets;

public class Blake2b {

    private static Blake2bDigest blake2b256Digest;
    private static Blake2bDigest blake2b384Digest;
    private static Blake2bDigest blake2b512Digest;

    public static Binary blake2b256Hash(byte[] value) {
        if(blake2b256Digest == null) blake2b256Digest = new Blake2bDigest(256);
        return blake2bHash(value, blake2b256Digest);
    }

    public static Binary blake2b256Hash(String value) {
        return blake2b256Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary blake2b384Hash(byte[] value) {
        if(blake2b384Digest == null) blake2b384Digest = new Blake2bDigest(384);
        return blake2bHash(value, blake2b384Digest);
    }

    public static Binary blake2b384Hash(String value) {
        return blake2b384Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary blake2b512Hash(byte[] value) {
        if(blake2b512Digest == null) blake2b512Digest = new Blake2bDigest(512);
        return blake2bHash(value, blake2b512Digest);
    }

    public static Binary blake2b512Hash(String value) {
        return blake2b512Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    private static Binary blake2bHash (byte[] value, Blake2bDigest digest) {
        byte[] rawHash = new byte[digest.getDigestSize()];
        digest.update(value, 0, value.length);
        digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }
}
