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
