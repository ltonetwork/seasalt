package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.crypto.digests.SHA384Digest;

import java.nio.charset.StandardCharsets;

public class SHA384 extends Hasher {

    private static SHA384Digest digest;

    public synchronized static Binary hash(byte[] value) {
        if(digest == null) digest = new SHA384Digest();
        return hash(value, digest);
    }

    public static Binary hash(String value) {
        return hash(value.getBytes(StandardCharsets.UTF_8));
    }

    public static Binary hash(Binary value) {
        return hash(value.getBytes());
    }
}
