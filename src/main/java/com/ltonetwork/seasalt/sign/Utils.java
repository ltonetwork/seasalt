package com.ltonetwork.seasalt.sign;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;

public class Utils{
    /**
     * Will automatically adjust the S component to be less than or equal to half the curve order,
     * if necessary. This is required because for every signature (r,s) the signature (r, -s (mod
     * N)) is a valid signature of the same message. However, we dislike the ability to modify the
     * bits of a Bitcoin transaction after it's been signed, as that violates various assumed
     * invariants. Thus in future only one of those forms will be considered legal and the other
     * will be banned.
     *
     * @return the signature in a canonicalised form
     */
    public static BigInteger toCanonicalised(BigInteger s, X9ECParameters curve, BigInteger halfCurveOrder) {
        if (!isCanonical(s, halfCurveOrder)) {
            // The order of the curve is the number of valid points that exist on that curve.
            // If S is in the upper half of the number of valid points, then bring it back to
            // the lower half. Otherwise, imagine that
            //    N = 10
            //    s = 8, so (-8 % 10 == 2) thus both (r, 8) and (r, 2) are valid solutions.
            //    10 - 8 == 2, giving us always the latter solution, which is canonical.
            return curve.getN().subtract(s);
        } else {
            return s;
        }
    }

    public static BigInteger toCanonicalised(BigInteger s) {
        return toCanonicalised(s, getSecp256k1Curve(), getSecp256k1HalfOrder());
    }

    /**
     * Converts BigInteger to byte array, without the sign bit.
     * The toByteArray() adds a prefix for negative numbers, however, in ECDSA we do not requir
     *
     * @return byte representation of the BigInteger, without sign bit
     */
    public static byte[] toBytesPadded(BigInteger value, int length) {
        byte[] result = new byte[length];
        byte[] bytes = value.toByteArray();

        int bytesLength;
        int srcOffset;
        if (bytes[0] == 0 && bytes.length != length) {
            bytesLength = bytes.length - 1;
            srcOffset = 1;
        } else {
            bytesLength = bytes.length;
            srcOffset = 0;
        }

        if (bytesLength > length) {
            throw new RuntimeException("Input is too large to put in byte array of size " + length);
        }

        int destOffset = length - bytesLength;
        System.arraycopy(bytes, srcOffset, result, destOffset, bytesLength);
        return result;
    }

    /**
     * @return true if the S component is "low", that means it is below
     * HALF_CURVE_ORDER. See <a
     * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures">
     * BIP62</a>.
     */
    private static boolean isCanonical(BigInteger s, BigInteger halfCurveOrder) {
        return s.compareTo(halfCurveOrder) <= 0;
    }

    public static byte[] derToRS(byte[] derSig, X9ECParameters curve, BigInteger halfCurveOrder) throws Exception {
        ASN1Primitive asn1 = toAsn1Primitive(derSig);
        if (asn1 instanceof ASN1Sequence) {
            ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
            ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            BigInteger r = asn1EncodableToBigInteger(asn1Encodables[0]);
            BigInteger s = Utils.toCanonicalised(asn1EncodableToBigInteger(asn1Encodables[1]), curve, halfCurveOrder);
            outputStream.write(toBytesPadded(r, 32));
            outputStream.write(toBytesPadded(s, 32));
            return outputStream.toByteArray();
        }
        return new byte[0];
    }

    public static byte[] derToRS(byte[] derSig) throws Exception {
        return derToRS(derSig, getSecp256k1Curve(), getSecp256k1HalfOrder());
    }


    private static BigInteger asn1EncodableToBigInteger(ASN1Encodable asn1Encodable) {
        ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
        if (asn1Primitive instanceof ASN1Integer) {
            ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
            return asn1Integer.getValue();
        }
        return new BigInteger(new byte[0]);
    }

    private static ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(data);
             ASN1InputStream asnInputStream = new ASN1InputStream(inStream))
        {
            return asnInputStream.readObject();
        }
    }

    private static X9ECParameters getSecp256k1Curve(){
        return SECNamedCurves.getByName("secp256k1");
    }

    private static BigInteger getSecp256k1HalfOrder(){
        X9ECParameters curve = getSecp256k1Curve();
        return curve.getN().shiftRight(1);
    }
}
