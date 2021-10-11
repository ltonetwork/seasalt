package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

abstract class ECDSABase implements Signer {
    final X9ECParameters curve;
    final ECDomainParameters domain;
    final ECGenParameterSpec spec;
    final BigInteger halfCurveOrder;
    final Digest digest;

    public ECDSABase(X9ECParameters curve, ECGenParameterSpec spec, Digest digest) {
        this.curve = curve;
        this.spec = spec;
        this.domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        this.halfCurveOrder = curve.getN().shiftRight(1);
        this.digest = digest;

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public ECDSABase(X9ECParameters curve, ECGenParameterSpec spec) {
        this(curve, spec, new SHA256Digest());
    }

    public ECDSABase(String curve) {
        this(SECNamedCurves.getByName(curve), new ECGenParameterSpec(curve), new SHA256Digest());
    }

    public KeyPair keyPair() {
        SecureRandom srSeed = new SecureRandom();
        return generateKeyPair(srSeed);
    }

    public KeyPair keyPairFromSeed(byte[] seed) {
        SecureRandom srSeed = new SecureRandom(seed);
        return generateKeyPair(srSeed);
    }

    /**
     * @param privateKey Private key bytes in ASN.1 format.
     * @return Key pair of the private key given and the derived public key.
     */
    public KeyPair keyPairFromSecretKey(byte[] privateKey) {
        byte[] publicKey = privateToPublic(privateKey);
        return new KeyPair(publicKey, privateKey);
    }

    public KeyPair keyPairFromSecretKey(Binary privateKey) {
        return keyPairFromSecretKey(privateKey.getBytes());
    }


    /**
     * Returns public key from the given private key.
     *
     * @param privKey the private key to derive the public key from
     * @return BigInteger encoded public key
     */
    protected byte[] privateToPublic(byte[] privKey) {
        ECPoint point = publicPointFromPrivate(new BigInteger(1, privKey));

        byte[] encoded = point.getEncoded(false);
        return new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length)).toByteArray(); // remove prefix
    }

    protected KeyPair generateKeyPair(SecureRandom seed) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            keyPairGenerator.initialize(spec, seed);
            java.security.KeyPair javaKeyPair = keyPairGenerator.generateKeyPair();
            BigInteger[] decodedASN1Keys = decodeASN1KeyPair(javaKeyPair);
            return new KeyPair(decodedASN1Keys[0].toByteArray(), decodedASN1Keys[1].toByteArray());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            throw new RuntimeException("Unknown external dependency error");
        }
    }


    /**
     * Decodes java.security.KeyPair from ASN.1 format to BigInteger which later can be
     * represented as 32 and 65 (64 + 1 byte, the 0x04 tag) bytes long private and public
     * keys, respectively.
     *
     * @param kp ASN.1 keypair to be decoded
     * @return decoded keypair
     */
    private BigInteger[] decodeASN1KeyPair(java.security.KeyPair kp) {
        BCECPrivateKey privateKey = (BCECPrivateKey) kp.getPrivate();
        BCECPublicKey publicKey = (BCECPublicKey) kp.getPublic();

        BigInteger privateKeyValue = privateKey.getD();

        // Ethereum does not use encoded public keys like bitcoin - see
        // https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm for details
        // Additionally, as the first bit is a constant prefix (0x04) we ignore this value
        byte[] publicKeyBytes = publicKey.getQ().getEncoded(false);
        BigInteger publicKeyValue =
                new BigInteger(1, Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length));
        return new BigInteger[]{publicKeyValue, privateKeyValue};
    }
}
