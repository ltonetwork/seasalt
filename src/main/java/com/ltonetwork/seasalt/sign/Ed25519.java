package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Ed25519 implements Signer {
    final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");

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

    public byte[] signDetached(byte[] msg, byte[] privateKey) {
        Ed25519Signer signer = new Ed25519Signer();
        AsymmetricKeyParameter privateKeyParameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(privateKey);
        signer.init(true, privateKeyParameters);
        signer.update(msg, 0, msg.length);
        return signer.generateSignature();
    }

    public byte[] signDetached(byte[] msg, KeyPair keypair) {
        return signDetached(msg, keypair.getPrivatekey());
    }

    public boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        Ed25519Signer verifier = new Ed25519Signer();
        AsymmetricKeyParameter publicKeyParameters = OpenSSHPublicKeyUtil.parsePublicKey(publicKey);
        verifier.init(false, publicKeyParameters);
        verifier.update(msg, 0, msg.length);
        return verifier.verifySignature(signature);
    }

    public boolean verify(byte[] msg, byte[] signature, KeyPair keypair) {
        return verify(msg, signature, keypair.getPublickey());
    }


    private byte[] privateToPublic(byte[] privateKey) {
        AsymmetricKeyParameter privateKeyParameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(privateKey);
        Ed25519PrivateKeyParameters sk = (Ed25519PrivateKeyParameters) privateKeyParameters;

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