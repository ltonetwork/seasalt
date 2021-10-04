package com.ltonetwork.seasalt.keypair;

import com.ltonetwork.seasalt.Binary;

public class ECDSAKeyPair extends KeyPair {
    ECDSAKeyType keyType;

    public ECDSAKeyPair(byte[] publicKey, byte[] privateKey, ECDSAKeyType keyType) {
        super(publicKey, privateKey);
        this.keyType = keyType;
    }

    public ECDSAKeyPair(Binary publicKey, Binary privateKey, ECDSAKeyType keyType) {
        super(publicKey, privateKey);
        this.keyType = keyType;
    }

    @Override
    public Binary getPublicKey() {
        switch(keyType) {
            case SECP256K1: return new Binary(compressPoint(this.publicKey.getBytes()));
            default: return this.publicKey;
        }
    }

    public Binary getPublicKeyUncompressed() {
        return this.publicKey;
    }

    private byte[] compressPoint(byte[] p) {
        int n = p.length;
        byte[] x = new byte[(n + 1)/2];
        byte[] y = new byte[n - x.length];

        System.arraycopy(p, 0, x, 0, x.length);
        System.arraycopy(p, x.length, y, 0, y.length);

        byte[] compressed = new byte[x.length + 1];
        compressed[0] = (byte) (2 + ( y[ y.length-1 ] & 1 ));
        System.arraycopy(x, 0, compressed, 0, x.length);

        return compressed;
    }
}
