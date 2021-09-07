package com.ltonetwork.seasalt.sign;

public class ECDSASignature extends Signature {
    private byte[] v;
    private final byte[] r;
    private final byte[] s;

    public ECDSASignature(byte[] r, byte[] s, byte[] v) {
        super(concatenateToSignature(v, r, s));
        this.v = v.clone();
        this.r = r.clone();
        this.s = s.clone();
    }

    public ECDSASignature(byte[] r, byte[] s, byte v) {
        this(r, s, new byte[]{v});
    }

    public ECDSASignature(byte[] r, byte[] s) {
        super(concatenateToSignature(r, s));
        this.r = r.clone();
        this.s = s.clone();
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public byte[] getV() {
        return v;
    }

    public String toDER() {
        String rHex = toHex(this.r);
        String rLengthHex = toHex(new byte[]{(byte) this.r.length}); // 20

        String sHex = toHex(this.s);
        String sLengthHex = toHex(new byte[]{(byte) this.s.length}); // 20

        String asn1Integer = "02";

        /** 4 extra bytes are allocated for
         * 1. one byte indicating the length of r (rLengthHex)
         * 2. one byte indicating the length of s (sLengthHex)
         * 3. two bytes (for r and s) indicating the following value as an integer (asn1Integer)
         */
        int sigLen = this.s.length + this.r.length + 4;
        String sigLenHex = toHex(new byte[]{(byte) sigLen});

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
