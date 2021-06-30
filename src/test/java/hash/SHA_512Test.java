package hash;

import com.ltonetwork.seasalt.hash.SHA_512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA_512Test {

    SHA_512 sha512;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha512 = new SHA_512();
        byteTest = new byte[]{-18, 38, -80, -35, 74, -9, -25, 73, -86, 26, -114, -29, -63, 10, -23, -110, 63, 97, -119, -128, 119, 46, 71, 63, -120, 25, -91, -44, -108, 14, 13, -78, 122, -63, -123, -8, -96, -31, -43, -8, 79, -120, -68, -120, 127, -42, 123, 20, 55, 50, -61, 4, -52, 95, -87, -83, -114, 111, 87, -11, 0, 40, -88, -1};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha512.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha512.hash("test").getBinary());
    }
}