package sign;

import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.Hasher;
import com.ltonetwork.seasalt.sign.ECDSA;
import com.ltonetwork.seasalt.sign.ECDSARecovery;
import com.ltonetwork.seasalt.sign.ECDSASignature;
import com.ltonetwork.seasalt.sign.Signature;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

public class ECDSASecp256k1Test {

    ECDSA secp256k1;
    Hasher hasher;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        secp256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"));
        hasher = new Hasher("Keccak-256");
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
        byte[] msg = hasher.hash("test").getBytes();

        Assertions.assertDoesNotThrow(() -> {
            secp256k1.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = hasher.hash("test").getBytes();
        Signature sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msg, sig, kp.getPublicKey().getBytes()));
    }

    @Test
    public void testVerifyDifferentKp() {
        ECDSARecovery secp256k1Recovery = new ECDSARecovery(SECNamedCurves.getByName("secp256k1"));
        KeyPair kpRecovery = secp256k1Recovery.keyPair();

        byte[] msg = hasher.hash("test").getBytes();
        ECDSASignature sig = secp256k1.signDetached(msg, kpRecovery.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msg, sig, kpRecovery.getPublicKey().getBytes()));
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
