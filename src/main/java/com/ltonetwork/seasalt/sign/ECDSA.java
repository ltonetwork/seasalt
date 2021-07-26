package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class ECDSA implements Signer {
    final X9ECParameters curve;
    final ECDomainParameters domain;
    final BigInteger HALF_CURVE_ORDER;
    final Digest digest;

    public ECDSA(X9ECParameters curve, Digest digest) {
        this.curve = curve;
        this.domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        this.HALF_CURVE_ORDER = curve.getN().shiftRight(1);
        this.digest = digest;
    }

    public ECDSA(X9ECParameters curve) {
        this(curve, new SHA256Digest());
    }

    public ECDSA(String curve) {
        this(SECNamedCurves.getByName(curve), new SHA256Digest());
    }

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

    public KeyPair keyPairFromSecretKey(Binary privateKey) {
        return keyPairFromSecretKey(privateKey.getBytes());
    }

//    public Binary signDetached(byte[] msg, byte[] privateKey) {
//        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(this.digest));
//        signer.init(true, new ECPrivateKeyParameters(new BigInteger(privateKey), domain));
//        BigInteger[] signature = signer.generateSignature(msg);
//        ByteArrayOutputStream baos = new ByteArrayOutputStream();
//        try {
//            DERSequenceGenerator seq = new DERSequenceGenerator(baos);
//            seq.addObject(new ASN1Integer(signature[0]));
//            seq.addObject(new ASN1Integer(toCanonicalS(signature[1])));
//            seq.close();
//            return new Binary(baos.toByteArray());
//        } catch (IOException e) {
//            return new Binary(new byte[0]);
//        }
//    }

    public ECDSASignature signDetached(byte[] msg, byte[] privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(this.digest));
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);
        byte[] r = toBytesPadded(signature[0], 32);
        byte[] s = toBytesPadded(toCanonicalS(signature[1]), 32);
        return new ECDSASignature(r, s);
    }

//    public boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
//        try (ASN1InputStream asn1 = new ASN1InputStream(signature)) {
//            ECDSASigner signer = new ECDSASigner();
//            signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), domain));
//
//            DLSequence seq = (DLSequence) asn1.readObject();
//            BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
//            BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
//            return signer.verifySignature(msg, r, s);
//        } catch (Exception e) {
//            return false;
//        }
//    }

    public boolean verify(byte[] msg, byte[] signature, byte[] publicKey) {
        int len = signature.length;
        byte[] r = Arrays.copyOfRange(signature, 0, len/2);
        byte[] s = Arrays.copyOfRange(signature, (len/2), len);

        return verify(msg, new ECDSASignature(r, s), publicKey);
    }

    public boolean verify(byte[] msg, ECDSASignature signature, byte[] publicKey) {
            ECDSASigner signer = new ECDSASigner();
            signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), domain));

            return signer.verifySignature(msg, new BigInteger(signature.getR()), new BigInteger(signature.getS()));
    }

    private byte[] privateToPublic(byte[] privateKey) {
        return curve.getG().multiply(new BigInteger(privateKey)).getEncoded(false);
    }

    private byte[] generatePrivateKey(SecureRandom seed) {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(domain, seed);
        generator.init(keygenParams);
        AsymmetricCipherKeyPair keypair = generator.generateKeyPair();
        ECPrivateKeyParameters privParams = (ECPrivateKeyParameters) keypair.getPrivate();
        return privParams.getD().toByteArray();
    }

    private BigInteger toCanonicalS(BigInteger s) {
        return s.compareTo(HALF_CURVE_ORDER) <= 0 ? s : curve.getN().subtract(s);
    }

    /**
     * Converts BigInteger to byte array, without the sign bit.
     * The toByteArray() adds a prefix for negative numbers, however, in ECDSA we do not requir
     *
     * @return byte representation of the BigInteger, without sign bit
     */
    private byte[] toBytesPadded(BigInteger value, int length) {
        byte[] result = new byte[length];
        byte[] bytes = value.toByteArray();

        int bytesLength;
        int srcOffset;
        if (bytes[0] == 0) {
            bytesLength = bytes.length - 1;
            srcOffset = 1;
        } else {
            bytesLength = bytes.length;
            srcOffset = 0;
        }

        if (bytesLength > length) {
            throw new RuntimeException("Input is too large to put in byte array of size " + length);
        }

        int destOffset = length - bytesLength;
        System.arraycopy(bytes, srcOffset, result, destOffset, bytesLength);
        return result;
    }
}
