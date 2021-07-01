package com.ltonetwork.seasalt;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bitcoinj.core.Base58;

import java.util.Base64;

public class Binary {
    byte[] digest;

    public Binary(byte[] digest) {
        this.digest = digest;
    }

    public byte[] getBytes() {
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

    public static byte[] fromHex(String hex) throws DecoderException {
        return Hex.decodeHex(hex);
    }

    public static byte[] fromBase58(String base58) {
        return Base58.decode(base58);
    }

    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}