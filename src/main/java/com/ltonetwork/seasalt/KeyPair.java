package com.ltonetwork.seasalt;

public class KeyPair {
    byte[] publickey;
    byte[] privatekey;

    public KeyPair(byte[] publickey, byte[] privatekey) {
        this.publickey = publickey;
        this.privatekey = privatekey;
    }

    public byte[] getPublickey() {
        return publickey;
    }

    public byte[] getPrivatekey() {
        return privatekey;
    }
}
