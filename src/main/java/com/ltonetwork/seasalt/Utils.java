package com.ltonetwork.seasalt;

import java.math.BigInteger;

public class Utils {

    /**
     * Encodes the given value as a unsigned Big Endian within an octet string
     * of octetStringSize bytes.
     *
     * @param i
     *            the integer to encode
     * @param octetStringSize
     *            the number of octets in the octetString returned
     * @return the encoding of i
     * @throws IllegalArgumentException
     *             if the given integer i is negative
     * @throws IllegalArgumentException
     *             if the octetStringSize is zero or lower
     * @throws IllegalArgumentException
     *             if the given BigInteger does not fit into octetStringSize
     *             bytes
     */
    public static byte[] integerToOctetString(final BigInteger i,
                                              final int octetStringSize) {

        // throws NullPointerException if i = null
        if (i.signum() < 0) {
            throw new IllegalArgumentException(
                    "argument i should not be negative");
        }

        if (octetStringSize <= 0) {
            throw new IllegalArgumentException("octetStringSize argument ("
                    + octetStringSize
                    + ") should be higher than 0 to store any integer");
        }

        if (i.bitLength() > octetStringSize * Byte.SIZE) {
            throw new IllegalArgumentException("argument i (" + i
                    + ") does not fit into " + octetStringSize + " octets");
        }

        final byte[] signedEncoding = i.toByteArray();
        final int signedEncodingLength = signedEncoding.length;

        if (signedEncodingLength == octetStringSize) {
            return signedEncoding;
        }

        final byte[] unsignedEncoding = new byte[octetStringSize];
        if (signedEncoding[0] == (byte) 0x00) {
            // skip first padding byte to create a (possitive) unsigned encoding for this number
            System.arraycopy(signedEncoding, 1, unsignedEncoding,
                    octetStringSize - signedEncodingLength + 1,
                    signedEncodingLength - 1);

        } else {
            System.arraycopy(signedEncoding, 0, unsignedEncoding,
                    octetStringSize - signedEncodingLength,
                    signedEncodingLength);
        }
        return unsignedEncoding;
    }

    /**
     * Returns a BigInteger that is the value represented by the unsigned, Big
     * Endian encoding within the given octetString.
     *
     * @param octetString
     *            the octetString containing (only) the encoding
     * @return the value represented by the octetString
     */
    public static BigInteger octetStringToInteger(final byte[] octetString) {
        // arguments are signum, magnitude as unsigned, Big Endian encoding
        return new BigInteger(1, octetString);
    }

    /**
     * Returns the minimum number of bytes required to directly store the given
     * number of bits.
     *
     * @param bitSize
     *            the bitSize
     * @return the size as a number of bytes
     * @throws IllegalArgumentException
     *             if the given bitSize argument is negative
     */
    public static int bitSizeToByteSize(final int bitSize) {
        if (bitSize < 0) {
            throw new IllegalArgumentException("bitSize (" + bitSize
                    + " should not be negative");
        }

        return (bitSize + Byte.SIZE - 1) / Byte.SIZE;
    }
}
