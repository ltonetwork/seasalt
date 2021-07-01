package hash;

import com.ltonetwork.seasalt.Binary;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BinaryTest {

    Binary binary;

    @BeforeEach
    public void init() {
        binary = new Binary(new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8});
    }

    @Test
    public void testGetBinary() {
        Assertions.assertArrayEquals(
                new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8},
                binary.getBytes());
    }

    @Test
    public void testGetHex() {
        Assertions.assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", binary.getHex());
    }

    @Test
    public void testGetBase58() {
        Assertions.assertEquals("Bjj4AWTNrjQVHqgWbP2XaxXz4DYH1WZMyERHxsad7b2w", binary.getBase58());
    }

    @Test
    public void testGetBase64() {
        Assertions.assertEquals("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=", binary.getBase64());
    }

    @Test
    public void testFromHex() throws DecoderException {
        Assertions.assertEquals(
                "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                Binary.fromHex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08").getHex()
        );
    }

    @Test
    public void testFromBase58() {
        Assertions.assertEquals(
                "Bjj4AWTNrjQVHqgWbP2XaxXz4DYH1WZMyERHxsad7b2w",
                Binary.fromBase58("Bjj4AWTNrjQVHqgWbP2XaxXz4DYH1WZMyERHxsad7b2w").getBase58()
        );
    }

    @Test
    public void testFromBase64() {
        Assertions.assertEquals(
                "n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=",
                Binary.fromBase64("n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=").getBase64()
        );
    }
}
