package hash;

import com.ltonetwork.seasalt.hash.SHA256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA256Test {

    SHA256 sha256;
    byte[] byteTest;
    String hexTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha256 = new SHA256();
        byteTest = new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8};
        hexTest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha256.hash("test".getBytes()));
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha256.hash("test"));
    }

    @Test
    public void testFromByteToHex() {
        Assertions.assertEquals(hexTest, sha256.hashToHex("test".getBytes()));
    }

    @Test
    public void testFromStringToHex() {
        Assertions.assertEquals(hexTest, sha256.hashToHex("test"));
    }
}