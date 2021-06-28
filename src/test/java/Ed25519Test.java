import com.ltonetwork.seasalt.Curve;
import com.ltonetwork.seasalt.Digest;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.Ed25519;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class Ed25519Test {

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = Ed25519.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = Ed25519.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testKeyPairFromSecretKey() {
        byte[] sk = Ed25519.keyPair().getPrivatekey();

        KeyPair myKeyPair = Ed25519.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivatekey());
        Assertions.assertNotNull(myKeyPair.getPublickey());
    }

    @Test
    public void testKeyPairFromSecretKeyFail() {
        Random rd = new Random();
        byte[] sk = new byte[12];
        rd.nextBytes(sk);

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            Ed25519.keyPairFromSecretKey(sk);
        });
    }

    @Test
    public void testSigns() {
        KeyPair kp = Ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            Ed25519.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = Ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Ed25519.signDetached(msg, kp.getPrivatekey());

        Assertions.assertTrue(Ed25519.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = Ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        byte[] sig = Ed25519.signDetached(msg, kp.getPrivatekey());

        Assertions.assertFalse(Ed25519.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
