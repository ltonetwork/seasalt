package com.ltonetwork.seasalt.sign;

import java.math.BigInteger;

public class ECDSASignature extends Signature {
    private byte[] v;
    private final BigInteger r;
    private final BigInteger s;

    public ECDSASignature(BigInteger r, BigInteger s, byte v, int sigLen) {
        //sigLen - 1 as the recovery bit is an addition to the original signature
        super(concatenateToSignature(new byte[]{v}, Utils.toBytesPadded(r, (sigLen-1)/2), Utils.toBytesPadded(s, (sigLen-1)/2)));
        this.v = new byte[]{v};
        this.r = r;
        this.s = s;
    }

    public ECDSASignature(BigInteger r, BigInteger s, int sigLen) {
        super(concatenateToSignature(Utils.toBytesPadded(r, sigLen/2), Utils.toBytesPadded(s, sigLen/2)));
        this.r = r;
        this.s = s;
    }

    public ECDSASignature(byte[] signature, boolean includesRecoveryKey) {
        super(signature);

        int n = signature.length;
        byte[] r = new byte[n/2];
        byte[] s = new byte[n/2];

        if(includesRecoveryKey) {
            System.arraycopy(signature, 1, r, 0, r.length);
            System.arraycopy(signature, r.length + 1, s, 0, s.length);
        } else {
            System.arraycopy(signature, 0, r, 0, r.length);
            System.arraycopy(signature, r.length, s, 0, s.length);
        }

        this.r = new BigInteger(1, r);
        this.s = new BigInteger(1, s);
        if(includesRecoveryKey) this.v = new byte[]{signature[0]};
    }

    public ECDSASignature(byte[] signature) {
        this(signature, false);
    }

    public BigInteger getR() {
        return r;
    }

    public BigInteger getS() {
        return s;
    }

    public byte[] getV() {
        return v;
    }

    public String toDER() {
        int sigLen = this.getBytes().length;
        byte[] rBytes = Utils.toBytesPadded(r, sigLen/2);
        byte[] sBytes = Utils.toBytesPadded(s, sigLen/2);
        String rHex = toHex(rBytes);
        String rLengthHex = toHex(new byte[]{(byte) rBytes.length}); // 20

        String sHex = toHex(sBytes);
        String sLengthHex = toHex(new byte[]{(byte) sBytes.length}); // 20

        String asn1Integer = "02";

        /** 4 extra bytes are allocated for
         * 1. one byte indicating the length of r (rLengthHex)
         * 2. one byte indicating the length of s (sLengthHex)
         * 3. two bytes (for r and s) indicating the following value as an integer (asn1Integer)
         */
        int DERSigLen = sigLen + 4;
        String sigLenHex = toHex(new byte[]{(byte) DERSigLen});

        String asn1Sequence = "30";

        return asn1Sequence +
                sigLenHex +
                asn1Integer +
                rLengthHex +
                rHex +
                asn1Integer +
                sLengthHex +
                sHex;
    }

    private String toHex(byte[] b) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

        char[] hexChars = new char[b.length * 2];
        for (int j = 0; j < b.length; j++) {
            int v = b[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static byte[] concatenateToSignature(byte[] v, byte[] r, byte[] s) {
        byte[] ret = new byte[v.length + r.length + s.length];
        System.arraycopy(v, 0, ret, 0, v.length);
        System.arraycopy(r, 0, ret, v.length, r.length);
        System.arraycopy(s, 0, ret, (v.length + r.length), s.length);
        return ret;
    }

    private static byte[] concatenateToSignature(byte[] r, byte[] s) {
        byte[] ret = new byte[r.length + s.length];
        System.arraycopy(r, 0, ret, 0, 32);
        System.arraycopy(s, 0, ret, 32, 32);
        return ret;
    }
}
