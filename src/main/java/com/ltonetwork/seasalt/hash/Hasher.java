package com.ltonetwork.seasalt.hash;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class Hasher {

    private static MessageDigest md;

    public static Binary hash(byte[] msg, String algorithm) {
        addSecurityProvider();
        getDigest(algorithm);
        return new Binary(md.digest(msg));
    }

    public static Binary hash(String msg, String algorithm) {
        addSecurityProvider();
        getDigest(algorithm);
        return new Binary(md.digest(msg.getBytes()));
    }

    public static Binary hash(Binary msg, String algorithm) {
        addSecurityProvider();
        getDigest(algorithm);
        return new Binary(md.digest(msg.getBytes()));
    }

    public static Binary hash(byte[] msg, MessageDigest algorithm) {
        addSecurityProvider();
        md = algorithm;
        return new Binary(md.digest(msg));
    }

    public static Binary hash(String msg, MessageDigest algorithm) {
        addSecurityProvider();
        md = algorithm;
        return new Binary(md.digest(msg.getBytes()));
    }

    public static Binary hash(Binary msg, MessageDigest algorithm) {
        addSecurityProvider();
        md = algorithm;
        return new Binary(md.digest(msg.getBytes()));
    }

    private static void getDigest(String algorithm) {
        try {
            md = MessageDigest.getInstance(algorithm, "BC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unknown algorithm" + algorithm);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException("Could not find BC provider");
        }
    }

    private static void addSecurityProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }
}
