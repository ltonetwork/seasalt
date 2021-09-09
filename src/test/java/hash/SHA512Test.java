package hash;

import com.ltonetwork.seasalt.hash.SHA512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA512Test {
    @Test
    public void testSHA_512Byte() {
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, SHA512.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_512String() {
        String hexRes = "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff";
        Assertions.assertEquals(hexRes, SHA512.hash("test").getHex());
    }
}
