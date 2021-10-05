package com.ltonetwork.seasalt.keypair;

import com.ltonetwork.seasalt.Binary;
import org.bouncycastle.asn1.sec.SECNamedCurves;

import java.math.BigInteger;
import java.util.Arrays;

public class ECDSAKeyPair extends KeyPair {
    ECDSAKeyType keyType;
    boolean compressed;

    public ECDSAKeyPair(byte[] publicKey, byte[] privateKey, ECDSAKeyType keyType, boolean compressed) {
        super(publicKey, privateKey);
        this.keyType = keyType;
        this.compressed = compressed;
    }

    public ECDSAKeyPair(Binary publicKey, Binary privateKey, ECDSAKeyType keyType, boolean compressed) {
        super(publicKey, privateKey);
        this.keyType = keyType;
        this.compressed = compressed;
    }

    public ECDSAKeyPair(byte[] publicKey, byte[] privateKey) {
        super(publicKey, privateKey);
        this.keyType = ECDSAKeyType.SECP256K1;
        this.compressed = false;
    }

    @Override
    public Binary getPublicKey() {
        switch(keyType) {
            case SECP256K1:
                if(compressed) return new Binary(compressPublicKey(this.publicKey.getBytes()));
                else return this.publicKey;
            case SECP256K1RECOVERY: return this.publicKey;
            default: throw new IllegalArgumentException("Unsupported key type");
        }
    }

    private byte[] compressPublicKey(byte[] publicKey) {
        BigInteger x;
        BigInteger y;
        if(publicKey.length == 65){
            x = new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33));
            y = new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65));
        }
        else {
            x = new BigInteger(1, Arrays.copyOfRange(publicKey, 0, 32));
            y = new BigInteger(1, Arrays.copyOfRange(publicKey, 32, 64));
        }
        return SECNamedCurves.getByName("secp256k1").getCurve().createPoint(x, y).getEncoded(true);
    }
}
