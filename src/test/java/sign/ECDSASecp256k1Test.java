package sign;

import com.ltonetwork.seasalt.Binary;
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
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
        hasher = new Hasher("Sha-256");
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
        Random rd = new Random();
        KeyPair kp = secp256k1.keyPair();
        for(int i=0; i<50; i++){
            byte[] msg = new byte[64];
            rd.nextBytes(msg);
            Signature sig = secp256k1.signDetached(hasher.hash(msg).getBytes(), kp.getPrivateKey().getBytes());

            Assertions.assertTrue(secp256k1.verify(hasher.hash(msg).getBytes(), sig, kp.getPublicKey().getBytes()));
        }
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
    public void testSignWithJWT() throws Exception {
        byte[] msg = hasher.hash("test").getBytes();

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
        byte[] realMsgHashed = hasher.hash(realMsg).getBytes();
        KeyPair seasaltKP = secp256k1.keyPairFromSecretKey(ecJWK.getD().decode());
        Assertions.assertTrue(secp256k1.verify(realMsgHashed, jwsObject.getSignature().decode(), seasaltKP));
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
        byte[] msgHashed = hasher.hash(msg).getBytes();

        java.security.Signature ecdsa = java.security.Signature.getInstance(ALGO);
        ecdsa.initSign(privateKey);
        ecdsa.update(msg);
        byte[] signature = ecdsa.sign();

        ecdsa.initVerify(publicKey);
        ecdsa.update(msg);
        boolean result = ecdsa.verify(signature);
        Assertions.assertTrue(result);

        // Seasalt
        KeyPair seasaltKp = secp256k1.keyPairFromSecretKey(privateKey.getS().toByteArray());
        byte[] rsSignature = derToRS(signature);
        Assertions.assertTrue(secp256k1.verify(msgHashed, rsSignature, seasaltKp));
    }

    private byte[] derToRS(byte[] derSig) throws Exception {
        ASN1Primitive asn1 = toAsn1Primitive(derSig);
        if (asn1 instanceof ASN1Sequence) {
            ASN1Sequence asn1Sequence = (ASN1Sequence) asn1;
            ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            BigInteger r = asn1EncodableToBigInteger(asn1Encodables[0]);
            BigInteger s = secp256k1.toCanonicalised(asn1EncodableToBigInteger(asn1Encodables[1]));
            outputStream.write(secp256k1.toBytesPadded(r, 32));
            outputStream.write(secp256k1.toBytesPadded(s, 32));
            return outputStream.toByteArray();
        }
        return new byte[0];
    }

    private BigInteger asn1EncodableToBigInteger(ASN1Encodable asn1Encodable) {
        ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
        if (asn1Primitive instanceof ASN1Integer) {
            ASN1Integer asn1Integer = (ASN1Integer) asn1Primitive;
            return asn1Integer.getValue();
        }
        return new BigInteger(new byte[0]);
    }

    private ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ByteArrayInputStream inStream = new ByteArrayInputStream(data);
             ASN1InputStream asnInputStream = new ASN1InputStream(inStream);)
        {
            return asnInputStream.readObject();
        }
    }
}
