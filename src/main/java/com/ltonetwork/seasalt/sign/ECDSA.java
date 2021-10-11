package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

public class ECDSA extends ECDSABase {

    final boolean compressed;

    public ECDSA(X9ECParameters curve, ECGenParameterSpec spec, Digest digest, boolean compressed) {
        super(curve, spec, digest);
        this.compressed = compressed;
    }

    public ECDSA(X9ECParameters curve, ECGenParameterSpec spec, Digest digest) {
        this(curve, spec, digest, true);
    }

    public ECDSA(X9ECParameters curve, ECGenParameterSpec spec, boolean compressed) {
        super(curve, spec);
        this.compressed = compressed;
    }

    public ECDSA(X9ECParameters curve, ECGenParameterSpec spec) {
        this(curve, spec, true);
    }

    public ECDSA(String curve, boolean compressed) {
        super(curve);
        this.compressed = compressed;
    }

    public ECDSA(String curve) {
        this(curve, true);
    }

    @Override
    public KeyPair keyPair() {
        return maybeCompress(super.keyPair());
    }

    @Override
    public KeyPair keyPairFromSeed(byte[] seed) {
        return maybeCompress(super.keyPairFromSeed(seed));
    }

    @Override
    public KeyPair keyPairFromSecretKey(byte[] privateKey) {
        return maybeCompress(super.keyPairFromSecretKey(privateKey));
    }

    @Override
    public KeyPair keyPairFromSecretKey(Binary privateKey) {
        return maybeCompress(super.keyPairFromSecretKey(privateKey));
    }

    private KeyPair maybeCompress(KeyPair keypair) {
        return compressed
            ? new KeyPair(
                new Binary(compressPublicKey(keypair.getPublicKey().getBytes())),
                keypair.getPrivateKey()
            )
            : keypair;
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
        byte[] pub = compressed ? decompressPublicKey(publicKey) : publicKey;

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(curve.getCurve().decodePoint(pub), domain);
        signer.init(false, params);

        BigInteger r = new BigInteger(1, signature.getR());
        BigInteger s = new BigInteger(1, signature.getS());

        return signer.verifySignature(msgHash, r, s);
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

        return verify(msgHash, new ECDSASignature(r, s), publicKey);
    }

    private byte[] compressPublicKey(byte[] publicKey) {
        BigInteger x;
        BigInteger y;
        if(publicKey.length == 65){
            x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33));
            y = new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65));
        }
        else {
            x = new BigInteger(1, Arrays.copyOfRange(publicKey, 0, 32));
            y = new BigInteger(1, Arrays.copyOfRange(publicKey, 32, 64));
        }
        return this.curve.getCurve().createPoint(x, y).getEncoded(true);
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
