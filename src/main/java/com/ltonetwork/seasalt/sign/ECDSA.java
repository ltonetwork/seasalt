package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ECDSA implements Signer {

    final X9ECParameters curve;
    final ECDomainParameters domain;
    final BigInteger halfCurveOrder;
    final Digest digest;
    boolean compressed;

    public ECDSA(X9ECParameters curve, Digest digest, boolean compressed) {
        this.curve = curve;
        this.domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        this.halfCurveOrder = curve.getN().shiftRight(1);
        this.digest = digest;
        this.compressed = compressed;
    }

    public ECDSA(X9ECParameters curve, Digest digest) {
        this(curve, digest, true);
    }

    public ECDSA(X9ECParameters curve, boolean compressed) {
        this(curve, new SHA256Digest());
        this.compressed = compressed;
    }

    public ECDSA(X9ECParameters curve) {
        this(curve, true);
    }

    public ECDSA(String curve, boolean compressed) {
        this(SECNamedCurves.getByName(curve), new SHA256Digest());
        this.compressed = compressed;
    }

    public ECDSA(String curve) {
        this(curve, true);
    }

    public KeyPair keyPair() {
        SecureRandom secureRandom = new SecureRandom();
        return generateKeyPair(secureRandom);
    }

    public KeyPair keyPairFromSeed(byte[] seed) {
        SecureRandom secureRandom = new SecureRandom(seed);
        return generateKeyPair(secureRandom);
    }

    public KeyPair keyPairFromSecretKey(byte[] privateKey) {
        byte[] publicKey = publicKeyFromPrivateKey(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair keyPairFromSecretKey(Binary privateKey) {
        return keyPairFromSecretKey(privateKey.getBytes());
    }

    public ECDSASignature signDetached(byte[] msg, byte[] privateKey) {
        ECDSASigner signerPriv = new ECDSASigner();
        signerPriv.init(true, BCPrivateKeyFromBytes(privateKey));
        BigInteger[] signature = signerPriv.generateSignature(msg);
        return new ECDSASignature(signature[0], signature[1]);
    }

    public ECDSASignature signDetachedCanonical(byte[] msg, byte[] privateKey) {
        ECDSASigner signerPriv = new ECDSASigner();
        signerPriv.init(true, BCPrivateKeyFromBytes(privateKey));
        BigInteger[] signature = signerPriv.generateSignature(msg);
        return new ECDSASignature(signature[0], Utils.toCanonicalised(signature[1]));
    }

    public boolean verify(byte[] msg, ECDSASignature signature, byte[] publicKey) {
        ECDSASigner signerPub = new ECDSASigner();
        signerPub.init(false, BCPublicKeyFromBytes(publicKey));
        return signerPub.verifySignature(msg, signature.getR(), signature.getS());
    }

    public boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        return verify(msg, new ECDSASignature(signature), publicKey);
    }


    private KeyPair generateKeyPair(SecureRandom secureRandom) {
        ECKeyGenerationParameters keyParams = new ECKeyGenerationParameters(domain, secureRandom);

        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keyParams);
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();
        byte[] sk = privateKey.getD().toByteArray();
        byte[] pk = publicKey.getQ().getEncoded(compressed);

        return new KeyPair(pk, sk);
    }

    private ECPrivateKeyParameters BCPrivateKeyFromBytes(byte[] privateKey) {
        return new ECPrivateKeyParameters(new BigInteger(privateKey), this.domain);
    }

    private ECPublicKeyParameters BCPublicKeyFromBytes(byte[] publicKey) {
        return new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), this.domain);
    }

    private byte[] BCPublicKeyToBytes(ECPublicKeyParameters publicKey) {
        return publicKey.getQ().getEncoded(compressed);
    }

    private byte[] publicKeyFromPrivateKey(byte[] privateKey) {
        ECPrivateKeyParameters privateKeyBC = BCPrivateKeyFromBytes(privateKey);
        ECPoint q = privateKeyBC.getParameters().getG().multiply(privateKeyBC.getD());
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(q, this.domain);
        return BCPublicKeyToBytes(publicKey);
    }
}
