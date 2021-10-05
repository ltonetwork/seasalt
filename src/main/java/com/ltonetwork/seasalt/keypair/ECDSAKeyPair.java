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
        byte[] x = new byte[32];
        byte[] y = new byte[32];

        if(p[0] == (byte) 0) System.arraycopy(p, 1, x, 0, x.length);
        else System.arraycopy(p, 0, x, 0, x.length);
        System.arraycopy(p, x.length, y, 0, y.length);

        byte[] compressed = new byte[x.length + 1];
        compressed[0] = (byte) (2 + ( y[ y.length-1 ] & 1 ));
        System.arraycopy(x, 0, compressed, 1, x.length);

        return compressed;
    }
}
