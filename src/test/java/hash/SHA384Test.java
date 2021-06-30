package hash;

import com.ltonetwork.seasalt.hash.SHA384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA384Test {

    SHA384 sha384;
    byte[] byteTest;

    @BeforeEach
    public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
        sha384 = new SHA384();
        byteTest = new byte[]{118, -124, 18, 50, 15, 123, 10, -91, -127, 47, -50, 66, -115, -60, 112, 107, 60, -82, 80, -32, 42, 100, -54, -95, 106, 120, 34, 73, -65, -24, -17, -60, -73, -17, 28, -53, 18, 98, 85, -47, -106, 4, 125, -2, -33, 23, -96, -87};
    }

    @Test
    public void testFromByteToByte() {
        Assertions.assertArrayEquals(byteTest, sha384.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testFromStringToByte() {
        Assertions.assertArrayEquals(byteTest, sha384.hash("test").getBinary());
    }
}