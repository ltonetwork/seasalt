package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import java.security.SecureRandom;

public class Ed25519 implements Signer {
    public KeyPair keyPair() {
        SecureRandom srSeed = new SecureRandom();
        byte[] privateKey = generatePrivateKey(srSeed);
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair keyPairFromSeed(byte[] seed) {
        SecureRandom srSeed = new SecureRandom(seed);
        byte[] privateKey = generatePrivateKey(srSeed);
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair keyPairFromSecretKey(byte[] privateKey) {
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public Signature signDetached(byte[] msg, byte[] privateKey) {
        Ed25519Signer signer = new Ed25519Signer();
        Ed25519PrivateKeyParameters privateKeyParameters = new Ed25519PrivateKeyParameters(privateKey);
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
        Ed25519PrivateKeyParameters sk = new Ed25519PrivateKeyParameters(privateKey);
        return sk.generatePublicKey().getEncoded();
    }

    private byte[] generatePrivateKey(SecureRandom seed) {
        Ed25519KeyPairGenerator generator = new Ed25519KeyPairGenerator();
        Ed25519KeyGenerationParameters keygenParams = new Ed25519KeyGenerationParameters(seed);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        Ed25519PrivateKeyParameters privParams = (Ed25519PrivateKeyParameters) keypair.getPrivate();
        return privParams.getEncoded();
    }
}
