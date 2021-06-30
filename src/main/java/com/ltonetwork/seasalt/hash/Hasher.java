package com.ltonetwork.seasalt.hash;

public interface Hasher {
    Digest hash(byte[] msg);

    Digest hash(String msg);
}
