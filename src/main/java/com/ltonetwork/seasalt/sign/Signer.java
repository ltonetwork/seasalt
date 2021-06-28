package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.KeyPair;

public interface Signer {

    static KeyPair keyPair() {
        return null;
    }

    static KeyPair keyPairFromSeed(byte[] seed) {
        return null;
    }

    static KeyPair keyPairFromSecretKey(byte[] seed) {
        return null;
    }

    static byte[] getPublicKeyFor(byte[] privateKey) {
        return new byte[0];
    }

    static byte[] signDetached(byte[] msg, byte[] privateKey) {
        return new byte[0];
    }

    static byte[] signDetached(byte[] msg, KeyPair keypair) {
        return new byte[0];
    }

    static boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        return false;
    }

    static boolean verify(byte[] msg, byte[] signature, KeyPair keypair) {
        return false;
    }
}
