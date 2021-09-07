package sign;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.Hasher;
import com.ltonetwork.seasalt.sign.Ed25519;
import com.ltonetwork.seasalt.sign.Signature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
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
    public void testKeyPairFromSeedAndNonce() {
        byte[] seed = new byte[]{-42, 20, -66, -118, -75, 113, 95, -8, -85, 70, 50, 81, -76, -75, -59, 113, -18, 101, 110, 98, 67, -74, -6, 66, 6, -40, 22, -18, -111, 121, -23, -61};
        int nonce = 1;
        byte[] actual_seed = Bytes.concat(Ints.toByteArray(nonce), seed);

        KeyPair myKeyPair = ed25519.keyPairFromSeed(actual_seed);

        Assertions.assertArrayEquals(
                myKeyPair.getPrivateKey().getBytes(),
                new byte[]{83, -69, -105, 5, 58, 122, -47, -83, 63, 15, -105, -56, -117, 48, 88, 79, 96, -102, 119, 47, -42, -40, 43, 110, -124, -38, 105, 12, -2, -54, -55, -94, -64, -54, 94, -105, 47, 81, 79, 39, 31, -38, -89, 12, -104, -96, -40, 86, 9, -76, 100, -56, 86, 33, 29, -105, -112, 29, 102, -4, 77, 120, 57, -47});
        Assertions.assertArrayEquals(
                myKeyPair.getPublicKey().getBytes(),
                new byte[]{-64, -54, 94, -105, 47, 81, 79, 39, 31, -38, -89, 12, -104, -96, -40, 86, 9, -76, 100, -56, 86, 33, 29, -105, -112, 29, 102, -4, 77, 120, 57, -47});
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
