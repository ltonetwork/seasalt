package hash;

import com.ltonetwork.seasalt.hash.SHA3_256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA3_256Test {

    SHA3_256 sha3_256;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha3_256 = new SHA3_256();
        byteTest = new byte[]{54, -16, 40, 88, 11, -80, 44, -56, 39, 42, -102, 2, 15, 66, 0, -29, 70, -30, 118, -82, 102, 78, 69, -18, -128, 116, 85, 116, -30, -11, -85, -128};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_256.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha3_256.hash("test").getBinary());
    }
}