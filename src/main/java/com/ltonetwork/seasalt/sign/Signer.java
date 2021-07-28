package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface Signer {

    KeyPair keyPair();

    KeyPair keyPairFromSeed(byte[] seed) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException;

    KeyPair keyPairFromSecretKey(byte[] privateKey);
    default KeyPair keyPairFromSecretKey(Binary privateKey) {
        return keyPairFromSecretKey(privateKey.getBytes());
    }

    Signature signDetached(byte[] msg, byte[] privateKey);
    default Signature signDetached(byte[] msg, Binary privateKey) {
        return signDetached(msg, privateKey.getBytes());
    }
    default Signature signDetached(byte[] msg, KeyPair keypair) {
        return signDetached(msg, keypair.getPrivateKey().getBytes());
    }
    default Signature signDetached(Binary msg, byte[] privateKey) {
        return signDetached(msg.getBytes(), privateKey);
    }
    default Signature signDetached(Binary msg, KeyPair keypair) {
        return signDetached(msg.getBytes(), keypair.getPrivateKey().getBytes());
    }
    default Signature signDetached(Binary msg, Binary privateKey) {
        return signDetached(msg.getBytes(), privateKey.getBytes());
    }
    default Signature signDetached(String msg, byte[] privateKey) {
        return signDetached(msg.getBytes(), privateKey);
    }
    default Signature signDetached(String msg, KeyPair keypair) {
        return signDetached(msg.getBytes(), keypair.getPrivateKey().getBytes());
    }
    default Signature signDetached(String msg, Binary privateKey) {
        return signDetached(msg.getBytes(), privateKey.getBytes());
    }

    boolean verify(byte[] msg, byte[] signature, byte[] publicKey);
    default boolean verify(byte[] msg, byte[] signature, KeyPair keypair) {
        return verify(msg, signature, keypair.getPublicKey().getBytes());
    }
    default boolean verify(byte[] msg, byte[] signature, Binary publicKey) {
        return verify(msg, signature, publicKey.getBytes());
    }
    default boolean verify(byte[] msg, Signature signature, byte[] publicKey) {
        return verify(msg, signature.getBytes(), publicKey);
    }
    default boolean verify(byte[] msg, Signature signature, Binary publicKey) {
        return verify(msg, signature.getBytes(), publicKey.getBytes());
    }
    default boolean verify(byte[] msg, Signature signature, KeyPair keypair) {
        return verify(msg, signature.getBytes(), keypair.getPublicKey().getBytes());
    }
    default boolean verify(Binary msg, byte[] signature, byte[] publicKey) {
        return verify(msg.getBytes(), signature, publicKey);
    }
    default boolean verify(Binary msg, byte[] signature, Binary publicKey) {
        return verify(msg.getBytes(), signature, publicKey.getBytes());
    }
    default boolean verify(Binary msg, byte[] signature, KeyPair keypair) {
        return verify(msg, signature, keypair.getPublicKey().getBytes());
    }
    default boolean verify(Binary msg, Signature signature, byte[] publicKey) {
        return verify(msg.getBytes(), signature.getBytes(), publicKey);
    }
    default boolean verify(Binary msg, Signature signature, Binary publicKey) {
        return verify(msg.getBytes(), signature.getBytes(), publicKey.getBytes());
    }
    default boolean verify(Binary msg, Signature signature, KeyPair keypair) {
        return verify(msg.getBytes(), signature.getBytes(), keypair.getPublicKey().getBytes());
    }
    default boolean verify(String msg, byte[] signature, byte[] publicKey) {
        return verify(msg.getBytes(), signature, publicKey);
    }
    default boolean verify(String msg, byte[] signature, Binary publicKey) {
        return verify(msg.getBytes(), signature, publicKey.getBytes());
    }
    default boolean verify(String msg, byte[] signature, KeyPair keypair) {
        return verify(msg.getBytes(), signature, keypair.getPublicKey().getBytes());
    }
    default boolean verify(String msg, Signature signature, byte[] publicKey) {
        return verify(msg.getBytes(), signature.getBytes(), publicKey);
    }
    default boolean verify(String msg, Signature signature, Binary publicKey) {
        return verify(msg.getBytes(), signature.getBytes(), publicKey.getBytes());
    }
    default boolean verify(String msg, Signature signature, KeyPair keypair) {
        return verify(msg.getBytes(), signature.getBytes(), keypair.getPublicKey().getBytes());
    }
}
