package com.ltonetwork.seasalt.hash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class SHA3_256 implements Hasher {

    MessageDigest md;

    public SHA3_256() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        md = MessageDigest.getInstance("SHA3-256", "BC");
    }

    public Digest hash(byte[] msg) {
        return new Digest(md.digest(msg));
    }

    public Digest hash(String msg) {
        return new Digest(md.digest(msg.getBytes()));
    }
}
