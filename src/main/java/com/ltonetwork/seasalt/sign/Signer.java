package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;

public interface Signer {

    KeyPair keyPair();

    KeyPair keyPairFromSeed(byte[] seed);

    KeyPair keyPairFromSecretKey(byte[] privateKey);
    KeyPair keyPairFromSecretKey(Binary privateKey);

    Binary signDetached(byte[] msg, byte[] privateKey);
    Binary signDetached(byte[] msg, KeyPair keypair);
    Binary signDetached(byte[] msg, Binary privateKey);
    Binary signDetached(Binary msg, byte[] privateKey);
    Binary signDetached(Binary msg, KeyPair keypair);
    Binary signDetached(Binary msg, Binary privateKey);
    Binary signDetached(String msg, byte[] privateKey);
    Binary signDetached(String msg, KeyPair keypair);
    Binary signDetached(String msg, Binary privateKey);

    boolean verify(byte[] msg, byte[] signature, byte[] publicKey);
    boolean verify(byte[] msg, byte[] signature, Binary publicKey);
    boolean verify(byte[] msg, byte[] signature, KeyPair keypair);
    boolean verify(byte[] msg, Binary signature, byte[] publicKey);
    boolean verify(byte[] msg, Binary signature, Binary publicKey);
    boolean verify(byte[] msg, Binary signature, KeyPair keypair);
    boolean verify(Binary msg, byte[] signature, byte[] publicKey);
    boolean verify(Binary msg, byte[] signature, Binary publicKey);
    boolean verify(Binary msg, byte[] signature, KeyPair keypair);
    boolean verify(Binary msg, Binary signature, byte[] publicKey);
    boolean verify(Binary msg, Binary signature, Binary publicKey);
    boolean verify(Binary msg, Binary signature, KeyPair keypair);
    boolean verify(String msg, byte[] signature, byte[] publicKey);
    boolean verify(String msg, byte[] signature, Binary publicKey);
    boolean verify(String msg, byte[] signature, KeyPair keypair);
    boolean verify(String msg, Binary signature, byte[] publicKey);
    boolean verify(String msg, Binary signature, Binary publicKey);
    boolean verify(String msg, Binary signature, KeyPair keypair);
}
