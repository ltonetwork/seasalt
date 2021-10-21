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
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ECDSA implements Signer {

    final X9ECParameters curve;
    final ECDomainParameters domain;
    final BigInteger halfCurveOrder;
    final Digest digest;
    final int sigLen;
    boolean compressed;

    public ECDSA(X9ECParameters curve, Digest digest, boolean compressed) {
        this.curve = curve;
        this.domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        this.halfCurveOrder = curve.getN().shiftRight(1);
        this.digest = digest;
        this.compressed = compressed;
        // X bits/8=Y bytes per signature element, signature is composed by r and s elements => *2
        this.sigLen = curve.getCurve().getFieldSize()/8*2;
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
        privateKey = addLeadingZero(privateKey);
        ECDSASigner signerPriv = new ECDSASigner();
        signerPriv.init(true, BCPrivateKeyFromBytes(privateKey));
        byte[] hashedMessage = hashMessage(msg);
        BigInteger[] signature = signerPriv.generateSignature(hashedMessage);
        return new ECDSASignature(signature[0], signature[1], sigLen);
    }

    public ECDSASignature signDetachedCanonical(byte[] msg, byte[] privateKey) {
        ECDSASigner signerPriv = new ECDSASigner();
        signerPriv.init(true, BCPrivateKeyFromBytes(privateKey));
        byte[] hashedMessage = hashMessage(msg);
        BigInteger[] signature = signerPriv.generateSignature(hashedMessage);
        return new ECDSASignature(signature[0], Utils.toCanonicalised(signature[1]), sigLen);
    }

    public boolean verify(byte[] msg, ECDSASignature signature, byte[] publicKey) {
        ECDSASigner signerPub = new ECDSASigner();
        signerPub.init(false, BCPublicKeyFromBytes(publicKey));
        byte[] hashedMessage = hashMessage(msg);
        return signerPub.verifySignature(hashedMessage, signature.getR(), signature.getS());
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

        return new KeyPair(pk, removeLeadingZero(sk));
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
        privateKey = addLeadingZero(privateKey);
        ECPrivateKeyParameters privateKeyBC = BCPrivateKeyFromBytes(privateKey);
        ECPoint q = privateKeyBC.getParameters().getG().multiply(privateKeyBC.getD());
        ECPublicKeyParameters publicKey = new ECPublicKeyParameters(q, this.domain);
        return BCPublicKeyToBytes(publicKey);
    }

    private byte[] addLeadingZero(byte[] privateKey) {
        if(privateKey.length == sigLen/2) {
            byte[] tmp = privateKey.clone();
            privateKey = new byte[sigLen/2+1];
            privateKey[0] = (byte) 0;
            System.arraycopy(tmp, 0, privateKey, 1, 32);
        }
        return privateKey;
    }

    private byte[] removeLeadingZero(byte[] privateKey) {
        if(privateKey.length == sigLen/2+1 && privateKey[0] == (byte) 0) {
            byte[] tmp = privateKey.clone();
            privateKey = new byte[sigLen/2];
            System.arraycopy(tmp, 1, privateKey, 0, 32);
        }
        return privateKey;
    }

    private byte[] hashMessage(byte[] msg) {
        digest.reset();
        digest.update(msg, 0, msg.length);
        byte[] result = new byte[digest.getDigestSize()];
        digest.doFinal(result, 0);
        return result;
    }
}
