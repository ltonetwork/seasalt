package com.ltonetwork.seasalt.hash;

import org.apache.commons.codec.DecoderException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.commons.codec.binary.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;

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

    public boolean verify(byte[] msg, byte[] hash) {
        return Arrays.equals(hash(msg), hash);
    }

    public boolean verify(String msg, byte[] hash) {
        return Arrays.equals(hash(msg.getBytes()), hash);
    }

    public boolean verifyFromHex(byte[] msg, String hash) throws DecoderException {
        return Arrays.equals(hash(msg), Hex.decodeHex(hash));
    }

    public boolean verifyFromHex(String msg, String hash) throws DecoderException {
        return Arrays.equals(hash(msg.getBytes()), Hex.decodeHex(hash));
    }
}
