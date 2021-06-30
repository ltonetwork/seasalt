package com.ltonetwork.seasalt.hash;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class SHA256 implements Hasher {

    MessageDigest md;

    public SHA256() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        md = MessageDigest.getInstance("SHA-256", "BC");
    }

    public byte[] hash(byte[] msg) {
        return md.digest(msg);
    }

    public byte[] hash(String msg) {
        return md.digest(msg.getBytes());
    }

    public String hashToHex(byte[] msg) {
        return Hex.encodeHexString(md.digest(msg));
    }

    public String hashToHex(String msg) {
        return Hex.encodeHexString(md.digest(msg.getBytes()));
    }
}
