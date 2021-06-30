package hash;

import com.ltonetwork.seasalt.hash.SHA1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA1Test {

    SHA1 sha1;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha1 = new SHA1();
        byteTest = new byte[]{-87, 74, -113, -27, -52, -79, -101, -90, 28, 76, 8, 115, -45, -111, -23, -121, -104, 47, -69, -45};
    }

    @Test
    public void testFromByteToByte() {
        System.out.println(sha1.hash("test".getBytes()).getHex());
        Assertions.assertArrayEquals(byteTest, sha1.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha1.hash("test").getBinary());
    }
}