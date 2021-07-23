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
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.custom.sec.*;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
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

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public ECDSA(X9ECParameters curve) {
        this(curve, new SHA256Digest());
    }

    public ECDSA(String curve) {
        this(SECNamedCurves.getByName(curve), new SHA256Digest());
    }

    public KeyPair keyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom srSeed = new SecureRandom();
        return generateKeyPair(srSeed);
    }

    public KeyPair keyPairFromSeed(byte[] seed) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
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
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);

        BigInteger r = signature[0];
        BigInteger s = toCanonicalised(signature[1]);

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

        byte[] rArr = toBytesPadded(r, 32);
        byte[] sArr = toBytesPadded(s, 32);
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
        if (signature.getBytes().length == 65) {
            return verifyRecoveryKey(msgHash, signature, publicKey);
        } else if (signature.getBytes().length == 64) {
            return verifyNoRecoveryKey(msgHash, signature, publicKey);
        } else {
            throw new IllegalArgumentException("Invalid signature length");
        }
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

        if (signature.length == 65) {
            byte[] v = new byte[1];
            System.arraycopy(signature, (r.length + s.length), v, 0, v.length);
            return verifyRecoveryKey(msgHash, new ECDSASignature(r, s, v), publicKey);
        } else if (signature.length == 64) {
            return verifyNoRecoveryKey(msgHash, new ECDSASignature(r, s), publicKey);
        } else {
            throw new IllegalArgumentException("Invalid signature length");
        }
    }

    /**
     * Verify signature using public key recovery from itself. Validate if the recovered public key
     * is the same as the one provided.
     *
     * More information you can find on: <a href="https://www.secg.org/sec1-v2.pdf">
     *     SEC 1: Elliptic Curve Cryptography</a>
     *
     * @param msgHash   hash of the data that was signed
     * @param signature the message signature components
     * @param publicKey the public key to be used to verify
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifyRecoveryKey(byte[] msgHash, ECDSASignature signature, byte[] publicKey) {
        BigInteger pubKeyRecovered = signedMessageToKey(msgHash, signature);
        return Arrays.equals(publicKey, pubKeyRecovered.toByteArray());
    }

    /**
     * Verify signature using the traditional verification method and the Bouncy Castle library.
     *
     * @param msgHash   hash of the data that was signed
     * @param signature the message signature components
     * @param publicKey the public key to be used to verify
     * @return true if the signature is valid, false otherwise
     */
    private boolean verifyNoRecoveryKey(byte[] msgHash, ECDSASignature signature, byte[] publicKey) {
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(curve.getCurve().decodePoint(publicKey), domain));

        return signer.verifySignature(msgHash, new BigInteger(signature.getR()), new BigInteger(signature.getS()));
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
    private BigInteger recoverFromSignature(int recId, BigInteger r, BigInteger s, byte[] msgHash) {
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
        //        routine specified in Section 2.3.7, where mlen = ⌈(log2 p)/8⌉ or mlen = ⌈m/8⌉.
        //   1.3. Convert the octet string (16 set binary digits)||X to an elliptic curve point R
        //        using the conversion routine specified in Section 2.3.4. If this conversion
        //        routine outputs "invalid", then do another iteration of Step 1.
        //
        // More concisely, what these points mean is to use X as a compressed public key.
        BigInteger prime = SecP256K1Curve.q;
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

    private KeyPair generateKeyPair(SecureRandom seed) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecGenParameterSpec, seed);
        java.security.KeyPair javaKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger[] decodedASN1Keys = decodeASN1KeyPair(javaKeyPair);
        return new KeyPair(decodedASN1Keys[0].toByteArray(), decodedASN1Keys[1].toByteArray());
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
        ECPoint point = publicPointFromPrivate(new BigInteger(privKey));

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

    /**
     * @return true if the S component is "low", that means it is below
     * HALF_CURVE_ORDER. See <a
     * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">
     * BIP62</a>.
     */
    private boolean isCanonical(BigInteger s) {
        return s.compareTo(HALF_CURVE_ORDER) <= 0;
    }

    /**
     * Will automatically adjust the S component to be less than or equal to half the curve order,
     * if necessary. This is required because for every signature (r,s) the signature (r, -s (mod
     * N)) is a valid signature of the same message. However, we dislike the ability to modify the
     * bits of a Bitcoin transaction after it's been signed, as that violates various assumed
     * invariants. Thus in future only one of those forms will be considered legal and the other
     * will be banned.
     *
     * @return the signature in a canonicalised form
     */
    private BigInteger toCanonicalised(BigInteger s) {
        if (!isCanonical(s)) {
            // The order of the curve is the number of valid points that exist on that curve.
            // If S is in the upper half of the number of valid points, then bring it back to
            // the lower half. Otherwise, imagine that
            //    N = 10
            //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
            //    10 - 8 == 2, giving us always the latter solution, which is canonical.
            return curve.getN().subtract(s);
        } else {
            return s;
        }
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
