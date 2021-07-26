package sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.ECDSA;
import com.ltonetwork.seasalt.sign.ECDSASignature;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class ECDSASecp256k1Test {

    ECDSA secp256k1;

    @BeforeEach
    public void init() {
        secp256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"));
    }

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = secp256k1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = secp256k1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKey() {
        byte[] sk = secp256k1.keyPair().getPrivateKey().getBytes();

        KeyPair myKeyPair = secp256k1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testSigns() {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            secp256k1.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Binary sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());
        ECDSASignature sig2 = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msg, sig, kp.getPublicKey().getBytes()));
        Assertions.assertTrue(secp256k1.verify(msg, sig2, kp.getPublicKey().getBytes()));
    }

    //FIXME:
//    @Test
//    public void testVerifyDifferentKp() {
//        ECDSARecovery secp256k1Recovery = new ECDSARecovery(SECNamedCurves.getByName("secp256k1"));
//
//        KeyPair kpRecovery = secp256k1Recovery.keyPair();
//
//        KeyPair kp = secp256k1.keyPair();
//
//        System.out.println(kpRecovery.getPrivateKey().getBytes().length);
//        System.out.println(kp.getPrivateKey().getBytes().length);
//        System.out.println(kpRecovery.getPublicKey().getBytes().length);
//        System.out.println(kp.getPublicKey().getBytes().length);
//
//        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
//        ECDSASignature sig = secp256k1Recovery.signDetached(msg, kp.getPrivateKey().getBytes());
//
//        Assertions.assertTrue(secp256k1Recovery.verify(msg, sig, kp.getPublicKey().getBytes()));
//    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Binary sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
