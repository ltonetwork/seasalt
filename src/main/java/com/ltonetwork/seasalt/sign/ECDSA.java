package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.keypair.ECDSAKeyPair;
import com.ltonetwork.seasalt.keypair.ECDSAKeyType;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

public class ECDSA extends ECDSARecovery implements Signer {

    public ECDSA(X9ECParameters curve, Digest digest) {
        super(curve, digest);
    }

    public ECDSA(X9ECParameters curve) {
        super(curve);
    }

    public ECDSA(String curve) {
        super(curve);
    }

    @Override
    public ECDSAKeyPair keyPair() {
        ECDSAKeyPair keypair = super.keyPair();
        return new ECDSAKeyPair(
                keypair.getPublicKey(),
                ECPointNoHeader(keypair.getPrivateKey(), 32),
                ECDSAKeyType.SECP256K1
        );
    }

    @Override
    public ECDSAKeyPair keyPairFromSeed(byte[] seed) {
        ECDSAKeyPair keypair = super.keyPairFromSeed(seed);
        return new ECDSAKeyPair(
                keypair.getPublicKey(),
                ECPointNoHeader(keypair.getPrivateKey(), 32),
                ECDSAKeyType.SECP256K1
        );
    }

    @Override
    public ECDSAKeyPair keyPairFromSecretKey(byte[] privateKey) {
        ECDSAKeyPair keypair = super.keyPairFromSecretKey(privateKey);
        return new ECDSAKeyPair(
                keypair.getPublicKey(),
                ECPointNoHeader(keypair.getPrivateKey(), 32),
                ECDSAKeyType.SECP256K1
        );
    }

    @Override
    public ECDSAKeyPair keyPairFromSecretKey(Binary privateKey) {
        ECDSAKeyPair keypair = super.keyPairFromSecretKey(privateKey);
        return new ECDSAKeyPair(
                keypair.getPublicKey(),
                ECPointNoHeader(keypair.getPrivateKey(), 32),
                ECDSAKeyType.SECP256K1
        );
    }

    private Binary ECPointNoHeader(Binary point, int targetLength) {
        byte[] out = new byte[targetLength];
        if(point.getBytes().length != targetLength) {
            System.arraycopy(point.getBytes(), 1, out, 0, targetLength);
            return new Binary(out);
        }
        else return point;
    }

    @Override
    public ECDSASignature signDetached(byte[] msg, byte[] privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(this.digest));
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(1, privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);

        BigInteger r = signature[0];
        BigInteger s = Utils.toCanonicalised(signature[1]);

        byte[] rArr = Utils.toBytesPadded(r, 32);
        byte[] sArr = Utils.toBytesPadded(s, 32);
        return new ECDSASignature(rArr, sArr);
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
        return verifyNoRecoveryKey(msgHash, signature, publicKey);
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
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, r.length);
        System.arraycopy(signature, r.length, s, 0, s.length);

        if(publicKey.length == 33) return verifyNoRecoveryKey(msgHash, new ECDSASignature(r, s), decompressPublicKey(publicKey));
        else return verifyNoRecoveryKey(msgHash, new ECDSASignature(r, s), publicKey);
    }

    private boolean verifyNoRecoveryKey(byte[] msgHash, ECDSASignature signatureData, byte[] publicKey) {
        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();

        // Workaround: conversion from Big Integer to byte[] adds header 0 for the sign
        // after decompressing the key this header byte is omitted, thus resulting in failing verification
        byte[] publicKeyLeadingZero = new byte[65];
        publicKeyLeadingZero[0] = (byte) 0;
        System.arraycopy(publicKey, 0, publicKeyLeadingZero, 1, 64);

        for (int i = 0; i < 4; i++) {
            BigInteger potentialKey = recoverFromSignature(i, new BigInteger(1, r), new BigInteger(1, s), msgHash);
            byte[] k = (potentialKey != null) ? potentialKey.toByteArray() : null;
            if (k != null && (Arrays.equals(publicKey, k) || Arrays.equals(publicKeyLeadingZero, k))) {
                return true;
            }
        }
        return false;
    }

    private byte[] decompressPublicKey(byte[] publicKey) {

        ECPoint point = curve.getCurve().decodePoint(publicKey);
        byte[] x = point.getXCoord().getEncoded();
        byte[] y = point.getYCoord().getEncoded();

        byte[] decomp = new byte[64];
        System.arraycopy(x, 0, decomp, 0, x.length);
        System.arraycopy(y, 0, decomp, x.length, y.length);

        return decomp;
    }
}
