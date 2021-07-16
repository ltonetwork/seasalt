package sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.ECDSA;
import com.ltonetwork.seasalt.sign.ECDSASignature;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;

public class ECDSASecp256k1Test {

    ECDSA secp256k1;

    @BeforeEach
    public void init() {
        secp256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"), "secp256k1");
    }

    @Test
    public void testKeyPair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair myKeyPair = secp256k1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = secp256k1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKey() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] sk = secp256k1.keyPair().getPrivateKey().getBytes();

        KeyPair myKeyPair = secp256k1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testSigns() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

//        System.out.println(Arrays.toString(kp.getPrivateKey().getBytes()));
//        System.out.println(Arrays.toString(kp.getPublicKey().getBytes()));

//        System.out.println(secp256k1.signDetached(msg, kp).getBytes().length);

        Assertions.assertDoesNotThrow(() -> {
            secp256k1.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        ECDSASignature sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPair kp = secp256k1.keyPair();
        X9ECParameters curve = SECNamedCurves.getByName("secp256k1");
        System.out.println(curve.getCurve());
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        ECDSASignature sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }

    @Test
    public void testSignWithWeb3() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECKeyPair ecKeyPair = Keys.createEcKeyPair();
        BigInteger privateKeyInDec = ecKeyPair.getPrivateKey();

        Sign.SignatureData signature = Sign.signMessage("test".getBytes(), ecKeyPair, false);

        KeyPair kp = secp256k1.keyPairFromSecretKey(privateKeyInDec.toByteArray());

        byte[] retval = new byte[64];
        System.arraycopy(signature.getR(), 0, retval, 0, 32);
        System.arraycopy(signature.getS(), 0, retval, 32, 32);
        System.out.println(Numeric.toHexString(retval));
        System.out.println(secp256k1.verify("test", retval, kp));
    }

    @Test
    public void testVerifyWithWeb3() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        ECKeyPair ecKeyPair = Keys.createEcKeyPair();
        BigInteger privateKeyInDec = ecKeyPair.getPrivateKey();

        for(int i=0; i<10; i++){
            Sign.SignatureData signature = Sign.signMessage("othsderioghsdf".getBytes(), ecKeyPair, false);

            System.out.println(signature.getR().length);
            System.out.println(signature.getS().length);
            System.out.println(signature.getV().length);
        }
//        KeyPair kp = secp256k1.keyPairFromSecretKey(privateKeyInDec.toByteArray());
//
//        byte[] sig = secp256k1.signDetached("test", kp).getBytes();

//        byte[] retval = new byte[65];
//        System.arraycopy(signature.getR(), 0, retval, 0, 32);
//        System.arraycopy(signature.getS(), 0, retval, 32, 32);
//        System.arraycopy(signature.getV(), 0, retval, 64, 1);
//        System.out.println(Numeric.toHexString(retval));
    }
}
