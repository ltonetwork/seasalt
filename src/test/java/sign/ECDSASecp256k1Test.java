package sign;

import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.Hasher;
import com.ltonetwork.seasalt.sign.ECDSA;
import com.ltonetwork.seasalt.sign.ECDSARecovery;
import com.ltonetwork.seasalt.sign.ECDSASignature;
import com.ltonetwork.seasalt.sign.Signature;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.StandardCharset;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
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

    @Test
    public void testSignWithJWT() throws JOSEException {
        byte[] msg = "test".getBytes();

        // Generate an EC key pair
        ECKey ecJWK = new ECKeyGenerator(Curve.SECP256K1)
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

        // Serialize the JWS to compact form
        String s = jwsObject.serialize();

        // The recipient creates a verifier with the public EC key
        JWSVerifier verifier = new ECDSAVerifier(ecPublicJWK);

        // Verify the EC signature
        Assertions.assertTrue(jwsObject.verify(verifier));
        Assertions.assertArrayEquals(msg, jwsObject.getPayload().toBytes());


        ECDSA seasalt = new ECDSA("secp256k1");
        byte[] realMsg = jwsObject.getSigningInput();
        byte[] privateKeyValue = ecJWK.getD().decode();
        KeyPair seasaltKP = seasalt.keyPairFromSecretKey(privateKeyValue);

        System.out.println("Signature JWS: " + jwsObject.getSignature().decode().length + " " + Arrays.toString(jwsObject.getSignature().decode()));
        System.out.println("Private: " + privateKeyValue.length + " " + Arrays.toString(privateKeyValue));
        System.out.println("Public: " + seasaltKP.getPublicKey().getBytes().length + " " + Arrays.toString(seasaltKP.getPublicKey().getBytes()));
        Assertions.assertTrue(seasalt.verify(realMsg, jwsObject.getSignature().decode(), seasaltKP.getPublicKey().getBytes()));
    }
}
