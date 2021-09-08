package hash;

import com.ltonetwork.seasalt.hash.SHA;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHATest {

    @Test
    public void testSHA_256Byte() {
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, SHA.SHA256Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_256String() {
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, SHA.SHA256Hash("test").getHex());
    }

    @Test
    public void testSHA_384Byte() {
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, SHA.SHA384Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_384String() {
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, SHA.SHA384Hash("test").getHex());
    }

    @Test
    public void testSHA_512Byte() {
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, SHA.SHA512Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_512String() {
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, SHA.SHA512Hash("test").getHex());
    }
}
