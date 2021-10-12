package sign;

import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.SHA256;
import com.ltonetwork.seasalt.sign.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

public class ECDSASecp256r1Test {

    ECDSA secp256r1;

    @BeforeEach
    public void init() {
        secp256r1 = new ECDSA(SECNamedCurves.getByName("secp256r1"), false);
    }

    @Test
    public void testKeyPair() {
        KeyPair myKeyPair = secp256r1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        KeyPair myKeyPair = secp256r1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKey() {
        byte[] sk = secp256r1.keyPair().getPrivateKey().getBytes();

        KeyPair myKeyPair = secp256r1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairCompression() {
        KeyPair myKeyPair = secp256r1.keyPair();

        Assertions.assertEquals(65, myKeyPair.getPublicKey().getBytes().length);

        ECDSA secp256k1Uncomp = new ECDSA(SECNamedCurves.getByName("secp256k1"), false);
        KeyPair myKeyPairUncomp = secp256k1Uncomp.keyPair();

        Assertions.assertTrue(
                myKeyPairUncomp.getPublicKey().getBytes().length == 64 ||
                myKeyPairUncomp.getPublicKey().getBytes().length == 65);
    }

    @Test
    public void testSigns() {
        KeyPair kp = secp256r1.keyPair();
        byte[] msg = SHA256.hash("test").getBytes();

        Assertions.assertDoesNotThrow(() -> {
            secp256r1.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        Random rd = new Random();
        KeyPair kp = secp256r1.keyPair();
        for (int i = 0; i < 50; i++) {
            byte[] msg = new byte[64];
            rd.nextBytes(msg);
            ECDSASignature sig = secp256r1.signDetached(SHA256.hash(msg).getBytes(), kp.getPrivateKey().getBytes());
            System.out.println("SK " + kp.getPrivateKey().getBytes().length + "b: " + kp.getPrivateKey().getHex());
            System.out.println("PK " + kp.getPublicKey().getBytes().length + "b: "  + kp.getPublicKey().getHex());
            System.out.println("SIG " + sig.getBytes().length + "b: " + sig.getHex());
            System.out.println("-----------------");

            Assertions.assertTrue(secp256r1.verify(SHA256.hash(msg).getBytes(), sig, kp.getPublicKey().getBytes()));
        }
    }

    @Test
    public void testVerifyFail() {
        KeyPair kp = secp256r1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = secp256r1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256r1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }
}
