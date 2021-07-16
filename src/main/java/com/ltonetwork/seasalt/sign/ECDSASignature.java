package com.ltonetwork.seasalt.sign;

import com.ltonetwork.seasalt.Binary;

public class ECDSASignature extends Binary {
    private final byte[] r;
    private final byte[] s;
    private byte[] v;

    public ECDSASignature(byte[] r, byte[] s, byte[] v) {
        super(concatenateToSignature(r, s, v));
        assert r.length==32;
        assert s.length==32;
        assert v.length==1;
        this.r = r.clone();
        this.s = s.clone();
        this.v = v.clone();
    }

    public ECDSASignature(byte[] r, byte[] s, byte v) {
        super(concatenateToSignature(r, s, new byte[]{v}));
        assert r.length==32;
        assert s.length==32;
        this.r = r.clone();
        this.s = s.clone();
        this.v = new byte[]{v};
    }

    public ECDSASignature(byte[] r, byte[] s) {
        super(concatenateToSignature(r, s));
        assert r.length==32;
        assert s.length==32;
        this.r = r.clone();
        this.s = s.clone();
    }

    public Binary getSignatureNoRecId() {
        byte[] ret = new byte[64];
        System.arraycopy(this.r, 0, ret, 0, 32);
        System.arraycopy(this.s, 0, ret, 32, 32);
        return new Binary(ret);
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

    public static byte[] concatenateToSignature(byte[] r, byte[] s, byte[] v) {
        byte[] ret = new byte[65];
        System.arraycopy(r, 0, ret, 0, 32);
        System.arraycopy(s, 0, ret, 32, 32);
        System.arraycopy(v, 0, ret, 64, 1);
        return ret;
    }

    public static byte[] concatenateToSignature(byte[] r, byte[] s) {
        byte[] ret = new byte[64];
        System.arraycopy(r, 0, ret, 0, 32);
        System.arraycopy(s, 0, ret, 32, 32);
        return ret;
    }
}
