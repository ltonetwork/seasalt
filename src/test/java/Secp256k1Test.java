import com.ltonetwork.seasalt.Curve;
import com.ltonetwork.seasalt.Digest;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.Secp256k1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class Secp256k1Test {

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = Secp256k1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
        Assertions.assertEquals(myKeyPair.getCurve(), Curve.SECP256k1);
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = Secp256k1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
        Assertions.assertEquals(myKeyPair.getCurve(), Curve.SECP256k1);
    }

    @Test
    public void testKeyPairFromSecretKey() {
        byte[] sk = Secp256k1.keyPair().getPrivatekey();

        KeyPair myKeyPair = Secp256k1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
        Assertions.assertEquals(myKeyPair.getCurve(), Curve.SECP256k1);
    }

    @Test
    public void testKeyPairFromSecretKeyFail() {
        Random rd = new Random();
        byte[] sk = new byte[12];
        rd.nextBytes(sk);

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            Secp256k1.keyPairFromSecretKey(sk);
        });
    }

    @Test
    public void testSigns() {
        KeyPair kp = Secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            Secp256k1.signDetached(msg, kp, Digest.SHA256);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = Secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Secp256k1.signDetached(msg, kp.getPrivatekey(), Digest.SHA256);

        Assertions.assertTrue(Secp256k1.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = Secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Secp256k1.signDetached(msg, kp.getPrivatekey(), Digest.SHA256);

        Assertions.assertFalse(Secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
