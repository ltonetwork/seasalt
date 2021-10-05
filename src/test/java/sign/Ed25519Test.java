package sign;

import com.goterl.lazysodium.SodiumJava;
import com.goterl.lazysodium.exceptions.SodiumException;
import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.keypair.Ed25519KeyPair;
import com.ltonetwork.seasalt.hash.SHA256;
import com.ltonetwork.seasalt.keypair.KeyPair;
import com.ltonetwork.seasalt.sign.Ed25519;
import com.ltonetwork.seasalt.sign.Signature;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Random;

import com.goterl.lazysodium.LazySodiumJava;

public class Ed25519Test {

    Ed25519 ed25519;
    LazySodiumJava lazySodium;

    @BeforeEach
    public void init() {
        ed25519 = new Ed25519();
        lazySodium = new LazySodiumJava(new SodiumJava());
    }

    @Test
    public void testKeyPair() {
        Ed25519KeyPair myKeyPair = ed25519.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        Ed25519KeyPair myKeyPair = ed25519.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeedAndNonce() {
        byte[] seed = new byte[]{-72, -39, -90, -96, 104, -56, -55, -33, -112, 4, -57, 50, -99, 55, -72, -116, 102, -113, -39, -88, -48, -103, -34, -60, 76, -51, -78, 92, 32, -53, -46, 115};

        Ed25519KeyPair myKeyPair = ed25519.keyPairFromSeed(seed);

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

        Ed25519KeyPair myKeyPair = ed25519.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk.getBytes(), myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKeyFail() {
        Random rd = new Random();
        byte[] sk = new byte[12];
        rd.nextBytes(sk);

        Assertions.assertThrows(IllegalArgumentException.class, () -> ed25519.keyPairFromSecretKey(sk));
    }

    @Test
    public void testSigns() {
        Ed25519KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);

        Assertions.assertDoesNotThrow(() -> {
            ed25519.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        Ed25519KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = ed25519.signDetached(msg, kp.getPrivateKey());

        Assertions.assertTrue(ed25519.verify(msg, sig, kp));
    }

    @Test
    public void testVerifyFail() {
        Ed25519KeyPair kp = ed25519.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = ed25519.signDetached(msg, kp.getPrivateKey());

        Assertions.assertFalse(ed25519.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }

    @Test
    public void testSameKeysAsNaClFromSeed() throws SodiumException {
        Random rd = new Random();
        byte[] seed = new byte[64];
        rd.nextBytes(seed);

        com.goterl.lazysodium.utils.KeyPair kpNaCl = lazySodium.cryptoSignSeedKeypair(SHA256.hash(seed).getBytes());
        Ed25519KeyPair kpSeaSalt = ed25519.keyPairFromSeed(seed);

        Assertions.assertArrayEquals(
                kpNaCl.getSecretKey().getAsBytes(),
                kpSeaSalt.getPrivateKey().getBytes()
        );

        Assertions.assertArrayEquals(
                kpNaCl.getPublicKey().getAsBytes(),
                kpSeaSalt.getPublicKey().getBytes()
        );
    }

    @Test
    public void testVerifyWithNaCl() {
        byte[] msgHash = SHA256.hash("test").getBytes();

        Ed25519KeyPair kpSeaSalt = ed25519.keyPair();
        Signature sigSeaSalt = ed25519.signDetached(msgHash, kpSeaSalt.getPrivateKey().getBytes());

        Assertions.assertTrue(
            lazySodium.cryptoSignVerifyDetached(
                sigSeaSalt.getBytes(),
                msgHash,
                msgHash.length,
                kpSeaSalt.getPublicKey().getBytes()
            )
        );
    }

    @Test
    public void testSignWithNaCl() throws SodiumException, DecoderException {
        String msgHash = SHA256.hash("test").getHex();

        com.goterl.lazysodium.utils.KeyPair kpNaCl = lazySodium.cryptoSignKeypair();
        String sigNaCl = lazySodium.cryptoSignDetached(msgHash,kpNaCl.getSecretKey());

        Assertions.assertTrue(ed25519.verify(msgHash, Binary.fromHex(sigNaCl).getBytes(), kpNaCl.getPublicKey().getAsBytes()));
    }

    @Test
    public void testNaClSeasaltFull() throws SodiumException, DecoderException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        String msgHash = SHA256.hash("test").getHex();

        // NaCl
        com.goterl.lazysodium.utils.KeyPair kpNaCl = lazySodium.cryptoSignKeypair();
        String sigNaCl = lazySodium.cryptoSignDetached(msgHash,kpNaCl.getSecretKey());

        Assertions.assertTrue(ed25519.verify(msgHash, Binary.fromHex(sigNaCl).getBytes(), kpNaCl.getPublicKey().getAsBytes()));

        // SEASALT
        Ed25519KeyPair kpSeaSalt = ed25519.keyPairFromSecretKey(kpNaCl.getSecretKey().getAsBytes());
        Signature sigSeaSalt = ed25519.signDetached(msgHash, kpSeaSalt.getPrivateKey().getBytes());

        Assertions.assertTrue(ed25519.verify(msgHash, sigSeaSalt, kpSeaSalt));

        Assertions.assertEquals(sigSeaSalt.getHex().toUpperCase(Locale.ROOT), sigNaCl);
    }
}
