package hash;

import com.ltonetwork.seasalt.hash.SHA3_384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA3_384Test {

    SHA3_384 sha3_384;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha3_384 = new SHA3_384();
        byteTest = new byte[]{-27, 22, -38, -69, 35, -74, -29, 0, 38, -122, 53, 67, 40, 39, -128, -93, -82, 13, -52, -16, 85, 81, -49, 2, -107, 23, -115, 127, -16, -15, -76, 30, -20, -71, -37, 63, -14, 25, 0, 124, 78, 9, 114, 96, -43, -122, 33, -67};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_384.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_384.hash("test").getBinary());
    }
}