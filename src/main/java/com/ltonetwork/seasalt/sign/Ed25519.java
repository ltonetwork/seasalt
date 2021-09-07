package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.Hasher;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Ed25519 implements Signer {
    public KeyPair keyPair() {
        SecureRandom srSeed = new SecureRandom();
        return keyPairFromSeed(srSeed.generateSeed(64));
    }

    public KeyPair keyPairFromSeed(byte[] seed) {
        byte[] privateKey = generatePrivateKey(seed);
        byte[] publicKey = privateToPublic(privateKey);
        byte[] concatenatedPrivateKey = new byte[64];
        System.arraycopy(privateKey, 0, concatenatedPrivateKey, 0, 32);
        System.arraycopy(publicKey, 0, concatenatedPrivateKey, 32, 32);
        return new KeyPair(publicKey, concatenatedPrivateKey);
    }

    public KeyPair keyPairFromSecretKey(byte[] privateKey) {
        byte[] actualPrivateKey = concatenatedPrivateToSeed(privateKey);
        byte[] publicKey = privateToPublic(actualPrivateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public Signature signDetached(byte[] msg, byte[] privateKey) {
        byte[] actualPrivateKey = concatenatedPrivateToSeed(privateKey);
        Ed25519Signer signer = new Ed25519Signer();
        Ed25519PrivateKeyParameters privateKeyParameters = new Ed25519PrivateKeyParameters(actualPrivateKey);
        signer.init(true, privateKeyParameters);
        signer.update(msg, 0, msg.length);
        return new Signature(signer.generateSignature());
    }

    public boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        Ed25519Signer verifier = new Ed25519Signer();
        Ed25519PublicKeyParameters publicKeyParameters = new Ed25519PublicKeyParameters(publicKey);
        verifier.init(false, publicKeyParameters);
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(signature);
    }

    private byte[] privateToPublic(byte[] privateKey) {
        byte[] actualPrivateKey = concatenatedPrivateToSeed(privateKey);
        Ed25519PrivateKeyParameters sk = new Ed25519PrivateKeyParameters(actualPrivateKey);
        return sk.generatePublicKey().getEncoded();
    }

    private byte[] generatePrivateKey(byte[] seed) {
        try {
            return new Hasher("SHA-256").hash(seed).getBytes();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Could not find SHA-256 and/or Blake2b-256 hashing algorithms");
        }
    }

    private byte[] concatenatedPrivateToSeed(byte[] privateKey) {
        if(!(privateKey.length == 32 || privateKey.length == 64))
            throw new IllegalArgumentException("Private key length should be either 32 or 64 bytes long");
        byte[] actualPrivateKey = new byte[32];
        System.arraycopy(privateKey, 0, actualPrivateKey, 0, 32);
        return actualPrivateKey;
    }
}
