package com.ltonetwork.seasalt.keypair;

import com.ltonetwork.seasalt.Binary;

public class Ed25519KeyPair extends KeyPair {
    public Ed25519KeyPair(byte[] publicKey, byte[] privateKey) {
        super(publicKey, privateKey);
    }

    public Ed25519KeyPair(Binary publicKey, Binary privateKey) {
        super(publicKey, privateKey);
    }
}
