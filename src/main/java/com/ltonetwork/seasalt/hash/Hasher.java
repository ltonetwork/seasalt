package com.ltonetwork.seasalt.hash;

import org.apache.commons.codec.DecoderException;

public interface Hasher {
    byte[] hash(byte[] msg);

    byte[] hash(String msg);

    String hashToHex(byte[] msg);

    String hashToHex(String msg);

    boolean verify(byte[] msg, byte[] hash);

    boolean verify(String msg, byte[] hash);

    boolean verifyFromHex(byte[] msg, String hash) throws DecoderException;

    boolean verifyFromHex(String msg, String hash) throws DecoderException;
}
