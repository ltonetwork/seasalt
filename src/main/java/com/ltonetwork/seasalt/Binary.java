package com.ltonetwork.seasalt;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import java.util.Base64;

public class Binary {
    byte[] bytes;

    public Binary(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public String getHex() {
        return Hex.encodeHexString(bytes);
    }

    public String getBase58() {
        return Base58.encode(bytes);
    }

    public String getBase64() {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static Binary fromHex(String hex) throws DecoderException {
        return new Binary(Hex.decodeHex(hex));
    }

    public static Binary fromBase58(String base58) {
        return new Binary(Base58.decode(base58));
    }

    public static Binary fromBase64(String base64) {
        return new Binary(Base64.getDecoder().decode(base64));
    }
}
