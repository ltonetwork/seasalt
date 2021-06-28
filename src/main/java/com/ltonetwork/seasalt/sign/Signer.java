package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.KeyPair;

public interface Signer {

    KeyPair keyPair();

    KeyPair keyPairFromSeed(byte[] seed);

    KeyPair keyPairFromSecretKey(byte[] seed);

    byte[] signDetached(byte[] msg, byte[] privateKey);

    byte[] signDetached(byte[] msg, KeyPair keypair);

    boolean verify(byte[] msg, byte[] signature, byte[] publicKey);

    boolean verify(byte[] msg, byte[] signature, KeyPair keypair);
}
