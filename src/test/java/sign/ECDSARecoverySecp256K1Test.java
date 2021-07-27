package sign;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.KeyPair;
import com.ltonetwork.seasalt.hash.Hasher;
import com.ltonetwork.seasalt.sign.ECDSA;
import com.ltonetwork.seasalt.sign.ECDSARecovery;
import com.ltonetwork.seasalt.sign.ECDSASignature;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Random;

public class ECDSARecoverySecp256K1Test {

    ECDSARecovery secp256k1;

    @BeforeEach
    public void init() {
        secp256k1 = new ECDSARecovery("secp256k1");
    }
    Hasher hasher = new Hasher("Keccak-256");

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
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = hasher.hash("test").getBytes();

        KeyPair kp = secp256k1.keyPair();

        Assertions.assertDoesNotThrow(() -> {
            secp256k1.signDetached(msgHash, kp);
        });
    }

    @Test
    public void testVerify() {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = hasher.hash("test").getBytes();

        KeyPair kp = secp256k1.keyPair();

        ECDSASignature sig = secp256k1.signDetached(msgHash, kp.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msgHash, sig, kp));
    }

    @Test
    public void testVerifyDifferentKp() {
        ECDSARecovery secp256k1NoRecovery = new ECDSA(SECNamedCurves.getByName("secp256k1"));
        KeyPair kpRecovery = secp256k1NoRecovery.keyPair();

        byte[] msgHash = hasher.hash("test").getBytes();
        ECDSASignature sig = secp256k1.signDetached(msgHash, kpRecovery.getPrivateKey().getBytes());

        Assertions.assertTrue(secp256k1.verify(msgHash, sig, kpRecovery.getPublicKey().getBytes()));
    }

    @Test
    public void testVerifyFail() {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = hasher.hash("test").getBytes();

        KeyPair kp = secp256k1.keyPair();
        Binary sig = secp256k1.signDetached(msgHash, kp.getPrivateKey().getBytes());

        Assertions.assertFalse(secp256k1.verify("fail".getBytes(StandardCharsets.UTF_8), sig, kp));
    }

    @Test
    public void testVerifyWithWeb3() throws SignatureException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = hasher.hash("test").getBytes();

        KeyPair kpSeaSalt = secp256k1.keyPair();
        ECDSASignature sigSeaSalt = secp256k1.signDetached(msgHash, kpSeaSalt.getPrivateKey().getBytes());

        Sign.SignatureData sigWeb3 = new Sign.SignatureData(sigSeaSalt.getV(), sigSeaSalt.getR(), sigSeaSalt.getS());
        BigInteger recoveredWeb3 = Sign.signedMessageHashToKey(msgHash, sigWeb3);
        Assertions.assertArrayEquals(kpSeaSalt.getPublicKey().getBytes(), recoveredWeb3.toByteArray());
    }

    @Test
    public void testSignWithWeb3() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = Hash.sha3(b);

        ECKeyPair kpWeb3 = Keys.createEcKeyPair();
        Sign.SignatureData sigWeb3 = Sign.signMessage(msgHash, kpWeb3, false);

        ECDSASignature sigSeaSalt = new ECDSASignature(sigWeb3.getR(), sigWeb3.getS(), sigWeb3.getV());

        Assertions.assertTrue(secp256k1.verify(msgHash, sigSeaSalt, kpWeb3.getPublicKey().toByteArray()));
    }

    @Test
    public void testWeb3SeasaltFull() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
        byte[] b = new byte[20];
        new Random().nextBytes(b);
        byte[] msgHash = Hash.sha3(b);

        // WEB3J
        ECKeyPair kpWeb3 = Keys.createEcKeyPair();
        Sign.SignatureData sigWeb3 = Sign.signMessage(msgHash, kpWeb3, false);

        BigInteger recoveredWeb3 = Sign.signedMessageHashToKey(msgHash, sigWeb3);

        Assertions.assertEquals(kpWeb3.getPublicKey(), recoveredWeb3);

        // SEASALT
        KeyPair kpSeaSalt = secp256k1.keyPairFromSecretKey(kpWeb3.getPrivateKey().toByteArray());
        ECDSASignature sigSeaSalt = secp256k1.signDetached(msgHash, kpSeaSalt.getPrivateKey().getBytes());

        Sign.SignatureData sig2Web3 = new Sign.SignatureData(sigSeaSalt.getV(), sigSeaSalt.getR(), sigSeaSalt.getS());
        BigInteger recoveredSeaSalt = Sign.signedMessageHashToKey(msgHash, sig2Web3);

        Assertions.assertArrayEquals(kpSeaSalt.getPublicKey().getBytes(), recoveredSeaSalt.toByteArray());

        Assertions.assertEquals(recoveredWeb3, recoveredSeaSalt);

    }
}
