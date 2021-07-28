package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class Hasher {

    MessageDigest md;

    public Hasher(MessageDigest md) {
        Security.addProvider(new BouncyCastleProvider());
        this.md = md;
    }

    public Hasher(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        this.md = MessageDigest.getInstance(algorithm, "BC");
    }

    public Binary hash(byte[] msg) {
        return new Binary(md.digest(msg));
    }

    public Binary hash(String msg) {
        return new Binary(md.digest(msg.getBytes()));
    }
}
