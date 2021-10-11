package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
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
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Locale;

public class ECDSARecovery implements Signer {
    final X9ECParameters curve;
    final ECDomainParameters domain;
    final BigInteger HALF_CURVE_ORDER;
    final Digest digest;

    public ECDSARecovery(X9ECParameters curve, Digest digest) {
        this.curve = curve;
        this.domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        this.HALF_CURVE_ORDER = curve.getN().shiftRight(1);
        this.digest = digest;

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public ECDSARecovery(X9ECParameters curve) {
        this(curve, new SHA256Digest());
    }

    public ECDSARecovery(String curve) {
        this(SECNamedCurves.getByName(curve), new SHA256Digest());
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

    public ECDSASignature signDetached(byte[] msg, byte[] privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(this.digest));
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(1, privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);

        BigInteger r = signature[0];
        BigInteger s = Utils.toCanonicalised(signature[1]);

        int recId = -1;
        BigInteger publicKey = new BigInteger(privateToPublic(privateKey));
        for (int i = 0; i < 4; i++) {
            BigInteger k = recoverFromSignature(i, r, s, msg);
            if (k != null && k.equals(publicKey)) {
                recId = i;
                break;
            }
        }
        if (recId == -1) {
            throw new RuntimeException(
                    "Could not construct a recoverable key. Are your credentials valid?");
        }
        int headerByte = recId + 27;

        byte[] rArr = Utils.toBytesPadded(r, 32);
        byte[] sArr = Utils.toBytesPadded(s, 32);
        byte[] vArr = new byte[]{(byte) headerByte};

        return new ECDSASignature(rArr, sArr, vArr);
    }

    /**
     * Verify signature using ECDSASignature structure for the signature.
     *
     * @param msgHash   hash of the data that was signed
     * @param signature the message signature components
     * @param publicKey the public key to be used to verify
     * @return true if the signature is valid, false otherwise
     */
    public boolean verify(byte[] msgHash, ECDSASignature signature, byte[] publicKey) {
        return verifyRecoveryKey(msgHash, signature, publicKey);
    }

    /**
     * Verify signature using byte array representation of the signature.
     *
     * @param msgHash   hash of the data that was signed
     * @param signature the message signature components
     * @param publicKey the public key to be used to verify
     * @return true if the signature is valid, false otherwise
     */
    public boolean verify(byte[] msgHash, byte[] signature, byte[] publicKey) {
        byte[] v = new byte[1];
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, v, 0, v.length);
        System.arraycopy(signature, v.length, r, 0, r.length);
        System.arraycopy(signature, (r.length + v.length), s, 0, s.length);

        return verifyRecoveryKey(msgHash, new ECDSASignature(r, s, v), publicKey);
    }

    /**
     * Verify signature using public key recovery from itself. Validate if the recovered public key
     * is the same as the one provided.
     * <p>
     * More information you can find on: <a href="https://www.secg.org/sec1-v2.pdf">
     * SEC 1: Elliptic Curve Cryptography</a>
     *
     * @param msgHash   hash of the data that was signed
     * @param signature the message signature components
     * @param publicKey the public key to be used to verify
     * @return true if the signature is valid, false otherwise
     */
    protected boolean verifyRecoveryKey(byte[] msgHash, ECDSASignature signature, byte[] publicKey) {
        BigInteger pubKeyRecovered = signedMessageToKey(msgHash, signature);
        if(publicKey.length == 33) {
            byte[] publicKeyDecompressed = decompressPublicKey(publicKey);
            // Workaround: conversion from Big Integer to byte[] adds header 0 for the sign
            // after decompressing the key this header byte is omitted, thus resulting in failing verification
            byte[] publicKeyLeadingZero = new byte[65];
            publicKeyLeadingZero[0] = (byte) 0;
            System.arraycopy(publicKeyDecompressed, 0, publicKeyLeadingZero, 1, 64);
            return Arrays.equals(publicKeyDecompressed, pubKeyRecovered.toByteArray())||
                    Arrays.equals(publicKeyLeadingZero, pubKeyRecovered.toByteArray());
        }
        return Arrays.equals(publicKey, pubKeyRecovered.toByteArray());
    }

    /**
     * Given the components of a signature and a selector value, recover and return the public key
     * that generated the signature according to the algorithm in SEC1v2 section 4.1.6.
     * <p>
     * The recId is an index from 0 to 3 which indicates which of the 4 possible keys is the
     * correct one. Because the key recovery operation yields multiple potential keys, the correct
     * key must either be stored alongside the signature, or you must be willing to try each recId
     * in turn until you find one that outputs the key you are expecting.
     * <p>
     * If this method returns null it means recovery was not possible and recId should be
     * iterated.
     * <p>
     * Given the above two points, a correct usage of this method is inside a for loop from 0 to
     * 3, and if the output is null OR a key that is not the one you expect, you try again with the
     * next recId.
     *
     * @param recId   which possible key to recover
     * @param r       the R component of the signature
     * @param s       the S component of the signature
     * @param msgHash hash of the data that was signed
     * @return an ECKey containing only the public part, or null if recovery wasn't possible
     */
    protected BigInteger recoverFromSignature(int recId, BigInteger r, BigInteger s, byte[] msgHash) {
        assert (recId >= 0);
        assert (r.signum() >= 0);
        assert (s.signum() >= 0);
        assert (msgHash != null);

        //   1.0 For j from 0 to h   (h == recId here and the loop is outside this function)
        //   1.1 Let x = r + jn
        BigInteger n = curve.getN(); // Curve order.
        BigInteger i = BigInteger.valueOf((long) recId / 2);
        BigInteger x = r.add(i.multiply(n));
        //   1.2. Convert the integer x to an octet string X of length mlen using the conversion
        //        routine specified in Section 2.3.7, where mlen = |(log2 p)/8| or mlen = |m/8|
        //        (N.B.: '|' is a ceiling function, but the proper ceiling symbol is not used as
        //        it is not in US-ASCII).
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R
        //        using the conversion routine specified in Section 2.3.4. If this conversion
        //        routine outputs "invalid", then do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = getPrime();
        if (x.compareTo(prime) >= 0) {
            // Cannot have point co-ordinates larger than this as everything takes place modulo Q.
            return null;
        }
        // Compressed keys require you to know an extra bit of data about the y-coord as there are
        // two possibilities. So it's encoded in the recId.
        ECPoint R = decompressKey(x, (recId & 1) == 1);
        //   1.4. If nR != point at infinity, then do another iteration of Step 1 (callers
        //        responsibility).
        if (!R.multiply(n).isInfinity()) {
            return null;
        }
        //   1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        BigInteger e = new BigInteger(1, msgHash);
        //   1.6. For k from 1 to 2 do the following.   (loop is outside this function via
        //        iterating recId)
        //   1.6.1. Compute a candidate public key as:
        //               Q = mi(r) * (sR - eG)
        //
        // Where mi(x) is the modular multiplicative inverse. We transform this into the following:
        //               Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
        // In the above equation ** is point multiplication and + is point addition (the EC group
        // operator).
        //
        // We can find the additive inverse by subtracting e from zero then taking the mod. For
        // example the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and
        // -3 mod 11 = 8.
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = rInv.multiply(s).mod(n);
        BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
        ECPoint q = ECAlgorithms.sumOfTwoMultiplies(curve.getG(), eInvrInv, R, srInv);

        byte[] qBytes = q.getEncoded(false);
        // We remove the prefix
        return new BigInteger(1, Arrays.copyOfRange(qBytes, 1, qBytes.length));
    }

    /**
     * Given an arbitrary message hash and an Ethereum message signature encoded in bytes, returns
     * the public key that was used to sign it. This can then be compared to the expected public key
     * to determine if the signature was correct.
     *
     * @param msgHash       the message hash
     * @param signatureData the message signature components
     * @return the public key used to sign the message
     */
    private BigInteger signedMessageToKey(byte[] msgHash, ECDSASignature signatureData) {

        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();
        assert signatureData.getR().length == 32;
        assert signatureData.getS().length == 32;

        int header = signatureData.getV()[0] & 0xFF;
        // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
        //                  0x1D = second key with even y, 0x1E = second key with odd y
        if (header < 27 || header > 34) {
            throw new IllegalArgumentException("Header byte out of range: " + header);
        }

        int recId = header - 27;
        BigInteger key = recoverFromSignature(recId, new BigInteger(1, r), new BigInteger(1, s), msgHash);
        System.out.println(key);
        if (key == null) {
            throw new IllegalArgumentException("Could not recover public key from signature");
        }
        return key;
    }

    private ECPoint decompressKey(BigInteger xBN, boolean yBit) {
        X9IntegerConverter x9 = new X9IntegerConverter();
        byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(curve.getCurve()));
        compEnc[0] = (byte) (yBit ? 0x03 : 0x02);
        return curve.getCurve().decodePoint(compEnc);
    }

    private KeyPair generateKeyPair(SecureRandom seed) {
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(deriveCurveName(this.domain));
            keyPairGenerator.initialize(ecGenParameterSpec, seed);
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

    /**
     * Returns public key from the given private key.
     *
     * @param privKey the private key to derive the public key from
     * @return BigInteger encoded public key
     */
    private byte[] privateToPublic(byte[] privKey) {
        ECPoint point = publicPointFromPrivate(new BigInteger(1, privKey));

        byte[] encoded = point.getEncoded(false);
        return new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length)).toByteArray(); // remove prefix
    }

    /**
     * Returns public key point from the given private key.
     *
     * @param privKey the private key to derive the public key from
     * @return ECPoint public key
     */
    private ECPoint publicPointFromPrivate(BigInteger privKey) {
        /*
         * TODO: FixedPointCombMultiplier currently doesn't support scalars longer than the group
         * order, but that could change in future versions.
         */
        if (privKey.bitLength() > curve.getN().bitLength()) {
            privKey = privKey.mod(curve.getN());
        }
        return new FixedPointCombMultiplier().multiply(curve.getG(), privKey);
    }

    protected byte[] decompressPublicKey(byte[] publicKey) {

        ECPoint point = curve.getCurve().decodePoint(publicKey);
        byte[] x = point.getXCoord().getEncoded();
        byte[] y = point.getYCoord().getEncoded();

        byte[] decomp = new byte[64];
        System.arraycopy(x, 0, decomp, 0, x.length);
        System.arraycopy(y, 0, decomp, x.length, y.length);

        return decomp;
    }

    private BigInteger getPrime() {
        String curveName = deriveCurveName(this.domain);
        String pckg = "org.bouncycastle.math.ec.custom.sec";
        // Get the package name of the curve class, i.e.: org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
        String fullQualifiedName = pckg + ".Sec" + curveName.substring(3).toUpperCase(Locale.ROOT) + "Curve";
        try{
            Class<?> cls = Class.forName(fullQualifiedName);
            ECCurve.AbstractFp abstractFp = (ECCurve.AbstractFp) cls.getDeclaredConstructor().newInstance();
            return abstractFp.getField().getCharacteristic();
        }
        catch(ClassNotFoundException | NoSuchMethodException | InvocationTargetException | InstantiationException | IllegalAccessException e) {
            throw new IllegalArgumentException("Unknown curve " + curveName);
        }

    }

    private String deriveCurveName(ECDomainParameters ecDomainParameters) {
        ECParameterSpec ecParameterSpec = new ECParameterSpec(
                ecDomainParameters.getCurve(),
                ecDomainParameters.getG(),
                ecDomainParameters.getN(),
                ecDomainParameters.getH(),
                ecDomainParameters.getSeed()
        );
        for (@SuppressWarnings("rawtypes")
             Enumeration names = ECNamedCurveTable.getNames(); names.hasMoreElements();){
            final String name = (String)names.nextElement();

            final X9ECParameters params = ECNamedCurveTable.getByName(name);

            if (params.getN().equals(ecParameterSpec.getN())
                    && params.getH().equals(ecParameterSpec.getH())
                    && params.getCurve().equals(ecParameterSpec.getCurve())
                    && params.getG().equals(ecParameterSpec.getG())){
                return ansiToSecg(name);
            }
        }

        throw new IllegalArgumentException("Could not find name for curve");
    }

    private String ansiToSecg(String ansi) {
        if(ansi.equals("prime192v1")) return "secp192r1";
        else if(ansi.equals("prime256v1")) return "secp256r1";
        else return ansi;
    }


}
