package com.ltonetwork.seasalt.hash;

import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;

import java.util.Base64;

public class Digest {
    byte[] digest;

    public Digest(byte[] digest) {
        this.digest = digest;
    }

    public byte[] getBinary() {
        return digest;
    }

    public String getHex() {
        return Hex.encodeHexString(digest);
    }

    public String getBase58() {
        return Base58.encode(digest);
    }

    public String getBase64() {
        return Base64.getEncoder().encodeToString(digest);
    }
}
