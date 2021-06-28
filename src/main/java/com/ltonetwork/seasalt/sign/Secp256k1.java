package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Curve;
import com.ltonetwork.seasalt.Digest;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Secp256k1 implements Signer {
    static final X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
    static final ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
    static final BigInteger HALF_CURVE_ORDER = curve.getN().shiftRight(1);

    public static KeyPair keyPair() {
        SecureRandom srSeed = new SecureRandom();
        byte[] privateKey = generatePrivateKey(srSeed);
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey, Curve.SECP256k1);
    }

    public static KeyPair keyPairFromSeed(byte[] seed) {
        SecureRandom srSeed = new SecureRandom(seed);
        byte[] privateKey = generatePrivateKey(srSeed);
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey, Curve.SECP256k1);
    }

    public static KeyPair keyPairFromSecretKey(byte[] privateKey) {
        if (privateKey.length == 32 || privateKey.length == 33) {
            byte[] publicKey = privateToPublic(privateKey);
            return new KeyPair(publicKey, privateKey, Curve.SECP256k1);

        } else throw new IllegalArgumentException("SECP256k1 private key should be 32 or 33 bytes long");
    }

    public static byte[] privateToPublic(byte[] privateKey) {
        return curve.getG().multiply(new BigInteger(privateKey)).getEncoded(true);
    }

    public static byte[] signDetached(byte[] msg, byte[] privateKey, Digest digest) {
        org.bouncycastle.crypto.Digest bouncyDigest = fetchDigest(digest);
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(bouncyDigest));
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
            seq.addObject(new ASN1Integer(signature[0]));
            seq.addObject(new ASN1Integer(toCanonicalS(signature[1])));
            seq.close();
            return baos.toByteArray();
        } catch (IOException e) {
            return new byte[0];
        }
    }

    public static byte[] signDetached(byte[] msg, KeyPair keypair, Digest digest) {
        if (keypair.getCurve() == Curve.SECP256k1) return signDetached(msg, keypair.getPrivatekey(), digest);
        else throw new IllegalArgumentException("Keypair curve missmatch");
    }

    public static byte[] signDetached(byte[] msg, byte[] privateKey) {
        return signDetached(msg, privateKey, Digest.SHA256);
    }

    public static byte[] signDetached(byte[] msg, KeyPair keypair) {
        if (keypair.getCurve() == Curve.SECP256k1) return signDetached(msg, keypair.getPrivatekey(), Digest.SHA256);
        else throw new IllegalArgumentException("Keypair curve missmatch");
    }

    public static boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        ASN1InputStream asn1 = new ASN1InputStream(signature);
        try {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), domain));

            DLSequence seq = (DLSequence) asn1.readObject();
            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
            return signer.verifySignature(msg, r, s);
        } catch (Exception e) {
            return false;
        } finally {
            try {
                asn1.close();
            } catch (IOException ignored) {
            }
        }
    }

    public static boolean verify(byte[] msg, byte[] signature, KeyPair keypair) {
        if (keypair.getCurve() == Curve.SECP256k1) return verify(msg, signature, keypair.getPublickey());
        else throw new IllegalArgumentException("Keypair curve missmatch");
    }

    private static org.bouncycastle.crypto.Digest fetchDigest(Digest digest) {
        switch (digest) {
            case SHA1:
                return new SHA1Digest();
            case SHA256:
                return new SHA256Digest();
            default:
                throw new IllegalArgumentException("Unknown digest for SECP256k1");
        }
    }

    private static byte[] generatePrivateKey(SecureRandom seed) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(domain, seed);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return privParams.getD().toByteArray();
    }

    private static BigInteger toCanonicalS(BigInteger s) {
        if (s.compareTo(HALF_CURVE_ORDER) <= 0) {
            return s;
        } else {
            return curve.getN().subtract(s);
        }
    }
}
