package hash;

import com.ltonetwork.seasalt.hash.SHA_256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA_256Test {

    SHA_256 sha256;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha256 = new SHA_256();
        byteTest = new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha256.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha256.hash("test").getBinary());
    }
}