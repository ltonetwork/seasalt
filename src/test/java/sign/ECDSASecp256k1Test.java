package sign;

import com.ltonetwork.seasalt.hash.SHA256;
import com.ltonetwork.seasalt.keypair.ECDSAKeyPair;
import com.ltonetwork.seasalt.sign.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.apache.commons.codec.DecoderException;
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

public class ECDSASecp256k1Test {

    ECDSA secp256k1;

    @BeforeEach
    public void init() {
        secp256k1 = new ECDSA(SECNamedCurves.getByName("secp256k1"));
    }

    @Test
    public void testKeyPair() {
        ECDSAKeyPair myKeyPair = secp256k1.keyPair();

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSeed() {
        Random rd = new Random();
        byte[] b = new byte[64];
        rd.nextBytes(b);

        ECDSAKeyPair myKeyPair = secp256k1.keyPairFromSeed(b);

        Assertions.assertNotNull(myKeyPair.getPrivateKey());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testKeyPairFromSecretKey() throws DecoderException {
        byte[] sk = secp256k1.keyPair().getPrivateKey().getBytes();

        ECDSAKeyPair myKeyPair = secp256k1.keyPairFromSecretKey(sk);

        Assertions.assertArrayEquals(sk, myKeyPair.getPrivateKey().getBytes());
        Assertions.assertNotNull(myKeyPair.getPublicKey());
    }

    @Test
    public void testSigns() {
        ECDSAKeyPair kp = secp256k1.keyPair();
        byte[] msg = SHA256.hash("test").getBytes();

        Assertions.assertDoesNotThrow(() -> {
            secp256k1.signDetached(msg, kp);
        });
    }

    @Test
    public void testVerify() {
        Random rd = new Random();
        ECDSAKeyPair kp = secp256k1.keyPair();
        for (int i = 0; i < 50; i++) {
            byte[] msg = new byte[64];
            rd.nextBytes(msg);
            Signature sig = secp256k1.signDetached(SHA256.hash(msg).getBytes(), kp.getPrivateKey().getBytes());

            Assertions.assertTrue(secp256k1.verify(SHA256.hash(msg).getBytes(), sig, kp.getPublicKey()));
        }
    }

    @Test
    public void testVerifyDifferentKp() {
        ECDSARecovery secp256k1Recovery = new ECDSARecovery(SECNamedCurves.getByName("secp256k1"));
        ECDSAKeyPair kpRecovery = secp256k1Recovery.keyPair();

        byte[] msg = SHA256.hash("test").getBytes();
        ECDSASignature sig = secp256k1.signDetached(msg, kpRecovery.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msg, sig, kpRecovery.getPublicKey().getBytes()));
    }

    @Test
    public void testVerifyFail() {
        ECDSAKeyPair kp = secp256k1.keyPair();
        byte[] msg = "test".getBytes(StandardCharsets.UTF_8);
        Signature sig = secp256k1.signDetached(msg, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }

    @Test
    public void testSignWithJWT() throws Exception {
        byte[] msg = SHA256.hash("test").getBytes();

        // Generate an EC key pair
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
                .keyID("123")
                .generate();
        ECKey ecPublicJWK = ecJWK.toPublicJWK();

        // Create the EC signer
        JWSSigner signer = new ECDSASigner(ecJWK);

        // Creates the JWS object with payload
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256K).keyID(ecJWK.getKeyID()).build(),
                new Payload(msg));

        // Compute the EC signature
        jwsObject.sign(signer);

        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        // Verify the EC signature
        Assertions.assertTrue(jwsObject.verify(verifier));
        Assertions.assertArrayEquals(msg, jwsObject.getPayload().toBytes());


        // Seasalt
        byte[] realMsg = jwsObject.getSigningInput();
        byte[] realMsgHashed = SHA256.hash(realMsg).getBytes();
        ECDSAKeyPair seasaltKP = secp256k1.keyPairFromSecretKey(ecJWK.getD().decode());
        Assertions.assertTrue(secp256k1.verify(realMsgHashed, jwsObject.getSignature().decode(), seasaltKP.getPublicKey()));
    }

    @Test
    public void testSignWithJavaSecurity() throws Exception {
        final String SPEC = "secp256k1";
        final String ALGO = "SHA256withECDSA";

        ECGenParameterSpec ecSpec = new ECGenParameterSpec(SPEC);
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(ecSpec, new SecureRandom());
        java.security.KeyPair keypair = g.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keypair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey) keypair.getPrivate();

        byte[] msg = "test".getBytes();
        byte[] msgHashed = SHA256.hash(msg).getBytes();

        java.security.Signature ecdsa = java.security.Signature.getInstance(ALGO);
        ecdsa.initSign(privateKey);
        ecdsa.update(msg);
        byte[] signature = ecdsa.sign();

        ecdsa.initVerify(publicKey);
        ecdsa.update(msg);
        boolean result = ecdsa.verify(signature);
        Assertions.assertTrue(result);

        // Seasalt
        ECDSAKeyPair seasaltKp = secp256k1.keyPairFromSecretKey(privateKey.getS().toByteArray());
        byte[] rsSignature = Utils.derToRS(signature);
        Assertions.assertTrue(secp256k1.verify(msgHashed, rsSignature, seasaltKp));
    }
}
