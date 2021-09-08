package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

import java.nio.charset.StandardCharsets;

public class SHA {

    private static SHA256Digest SHA256Digest;
    private static SHA384Digest SHA384Digest;
    private static SHA512Digest SHA512Digest;

    public static Binary SHA256Hash(byte[] value) {
        if(SHA256Digest == null) SHA256Digest = new SHA256Digest();
        byte[] rawHash = new byte[SHA256Digest.getDigestSize()];
        SHA256Digest.update(value, 0, value.length);
        SHA256Digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary SHA256Hash(String value) {
        return SHA256Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary SHA384Hash(byte[] value) {
        if(SHA384Digest == null) SHA384Digest = new SHA384Digest();
        byte[] rawHash = new byte[SHA384Digest.getDigestSize()];
        SHA384Digest.update(value, 0, value.length);
        SHA384Digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary SHA384Hash(String value) {
        return SHA384Hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary SHA512Hash(byte[] value) {
        if(SHA512Digest == null) SHA512Digest = new SHA512Digest();
        byte[] rawHash = new byte[SHA512Digest.getDigestSize()];
        SHA512Digest.update(value, 0, value.length);
        SHA512Digest.doFinal(rawHash, 0);
        return new Binary(rawHash);
    }

    public static Binary SHA512Hash(String value) {
        return SHA512Hash(value.getBytes(StandardCharsets.UTF_8));
    }
}
