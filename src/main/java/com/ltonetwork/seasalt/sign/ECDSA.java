package com.ltonetwork.seasalt.sign;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

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
    public ECDSASignature signDetached(byte[] msg, byte[] privateKey) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(this.digest));
        signer.init(true, new ECPrivateKeyParameters(new BigInteger(privateKey), domain));
        BigInteger[] signature = signer.generateSignature(msg);

        BigInteger r = signature[0];
        BigInteger s = toCanonicalised(signature[1]);

        byte[] rArr = toBytesPadded(r, 32);
        byte[] sArr = toBytesPadded(s, 32);
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

        return verifyNoRecoveryKey(msgHash, new ECDSASignature(r, s), publicKey);
    }

    private boolean verifyNoRecoveryKey(byte[] msgHash, ECDSASignature signatureData, byte[] publicKey) {
        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();

        for (int i = 0; i < 4; i++) {
            BigInteger potentialKey = recoverFromSignature(i, new BigInteger(1, r), new BigInteger(1, s), msgHash);
            byte[] k = (potentialKey != null) ? potentialKey.toByteArray() : null;
            if (k != null && Arrays.equals(publicKey, k)) {
                return true;
            }
        }
        return false;
    }
}
