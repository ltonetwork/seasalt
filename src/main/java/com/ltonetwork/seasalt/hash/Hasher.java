package com.ltonetwork.seasalt.hash;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Hasher {

    MessageDigest md;

    public Hasher(MessageDigest md) throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        this.md = md;
    }

    public Hasher(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        this.md = MessageDigest.getInstance(algorithm, "BC");
    }

    public Digest hash(byte[] msg) {
        return new Digest(md.digest(msg));
    }

    public Digest hash(String msg) {
        return new Digest(md.digest(msg.getBytes()));
    }
}
