import com.ltonetwork.seasalt.Digest;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.ECDSA;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class ECDSASecp256k1Test {

    ECDSA SECP256k1;

    @BeforeEach
    public void init() {
        SECP256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"));
    }

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = SECP256k1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = SECP256k1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testKeyPairFromSecretKey() {
        byte[] sk = SECP256k1.keyPair().getPrivatekey();

        KeyPair myKeyPair = SECP256k1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testSigns() {
        KeyPair kp = SECP256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            SECP256k1.signDetached(msg, kp, Digest.SHA256);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = SECP256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = SECP256k1.signDetached(msg, kp.getPrivatekey(), Digest.SHA256);

        Assertions.assertTrue(SECP256k1.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = SECP256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = SECP256k1.signDetached(msg, kp.getPrivatekey(), Digest.SHA256);

        Assertions.assertFalse(SECP256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
