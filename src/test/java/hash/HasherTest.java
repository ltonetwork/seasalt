package hash;

import com.ltonetwork.seasalt.hash.Hasher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class HasherTest {

    @Test
    public void testSHA_256Byte() {
        String algorithm = "SHA-256";
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA_256String() {
        String algorithm = "SHA-256";
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testSHA_384Byte() {
        String algorithm = "SHA-384";
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA_384String() {
        String algorithm = "SHA-384";
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testSHA_512Byte() {
        String algorithm = "SHA-512";
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA_512String() {
        String algorithm = "SHA-512";
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testSHA3_256Byte() {
        String algorithm = "SHA3-256";
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA3_256String() {
        String algorithm = "SHA3-256";
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testSHA3_384Byte() {
        String algorithm = "SHA3-384";
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA3_384String() {
        String algorithm = "SHA3-384";
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testSHA3_512Byte() {
        String algorithm = "SHA3-512";
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testSHA3_512String() {
        String algorithm = "SHA3-512";
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testBlake2b_256Byte() {
        String algorithm = "Blake2b-256";
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testBlake2b_256String() {
        String algorithm = "Blake2b-256";
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testBlake2b_384Byte() {
        String algorithm = "Blake2b-384";
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testBlake2b_384String() {
        String algorithm = "Blake2b-384";
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testBlake2b_512Byte() {
        String algorithm = "Blake2b-512";
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testBlake2b_512String() {
        String algorithm = "Blake2b-512";
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testKeccak_256Byte() {
        String algorithm = "Keccak-256";
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testKeccak_256String() {
        String algorithm = "Keccak-256";
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testKeccak_384Byte() {
        String algorithm = "Keccak-384";
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testKeccak_384String() {
        String algorithm = "Keccak-384";
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }

    @Test
    public void testKeccak_512Byte() {
        String algorithm = "Keccak-512";
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Hasher.hash("test".getBytes(), algorithm).getHex());
    }

    @Test
    public void testKeccak_512String() {
        String algorithm = "Keccak-512";
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Hasher.hash("test", algorithm).getHex());
    }
}
