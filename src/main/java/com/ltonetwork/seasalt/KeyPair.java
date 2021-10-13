package com.ltonetwork.seasalt;

import com.ltonetwork.seasalt.Binary;

public class KeyPair {
    Binary publicKey;
    Binary privateKey;

    public KeyPair(byte[] publicKey, byte[] privateKey) {
        this.publicKey = new Binary(publicKey);
        this.privateKey = new Binary(privateKey);
    }

    public KeyPair(Binary publicKey, Binary privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public Binary getPublicKey() {
        return publicKey;
    }

    public Binary getPrivateKey() {
        return privateKey;
    }
}
