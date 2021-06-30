package hash;

import com.ltonetwork.seasalt.hash.Digest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class DigestTest {

    Digest digest;

    @BeforeEach
    public void init() {
        digest = new Digest(new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8});
    }

    @Test
    public void testGetBinary() {
        Assertions.assertArrayEquals(
                new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8},
                digest.getBinary());
    }

    @Test
    public void testGetHex() {
        Assertions.assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", digest.getHex());
    }

    @Test
    public void testGetBase58() {
        Assertions.assertEquals("Bjj4AWTNrjQVHqgWbP2XaxXz4DYH1WZMyERHxsad7b2w", digest.getBase58());
    }

    @Test
    public void testGetBase64() {
        Assertions.assertEquals("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", digest.getBase64());
    }
}
