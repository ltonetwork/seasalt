package com.ltonetwork.seasalt;

public class KeyPair {
    byte[] publickey;
    byte[] privatekey;
    Curve curve;

    public KeyPair(byte[] publickey, byte[] privatekey, Curve curve) {
        this.publickey = publickey;
        this.privatekey = privatekey;
        this.curve = curve;
    }

    public byte[] getPublickey() {
        return publickey;
    }

    public byte[] getPrivatekey() {
        return privatekey;
    }

    public Curve getCurve() {
        return curve;
    }
}
