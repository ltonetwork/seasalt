package com.ltonetwork.seasalt.hash;

public interface Hasher {
    byte[] hash(byte[] msg);

    byte[] hash(String msg);

    String hashToHex(byte[] msg);

    String hashToHex(String msg);
}
