package hash;

import com.ltonetwork.seasalt.hash.SHA3_512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA3_512Test {

    SHA3_512 sha3_512;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha3_512 = new SHA3_512();
        byteTest = new byte[]{-98, -50, 8, 110, -101, -84, 73, 31, -84, 92, 29, 16, 70, -54, 17, -41, 55, -71, 42, 43, 46, -67, -109, -16, 5, -41, -73, 16, 17, 12, 10, 103, -126, -120, 22, 110, 127, -66, 121, 104, -125, -92, -14, -23, -77, -54, -97, 72, 79, 82, 29, 12, -28, 100, 52, 92, -63, -82, -55, 103, 121, 20, -100, 20};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_512.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_512.hash("test").getBinary());
    }
}