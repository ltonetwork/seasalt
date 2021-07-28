package sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.sign.Ed25519;
import com.ltonetwork.seasalt.sign.Signature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Random;

public class Ed25519Test {

    Ed25519 ed25519;

    @BeforeEach
    public void init() {
        ed25519 = new Ed25519();
    }

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = ed25519.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = ed25519.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKey() {
        Binary sk = ed25519.keyPair().getPrivateKey();

        KeyPair myKeyPair = ed25519.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk.getBytes(), myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKeyFail() {
        Random rd = new Random();
        byte[] sk = new byte[12];
        rd.nextBytes(sk);

        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            ed25519.keyPairFromSecretKey(sk);
        });
    }

    @Test
    public void testSigns() {
        KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            ed25519.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = ed25519.signDetached(msg, kp.getPrivateKey());

        Assertions.assertTrue(ed25519.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = ed25519.signDetached(msg, kp.getPrivateKey());

        Assertions.assertFalse(ed25519.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
