package hash;

import com.ltonetwork.seasalt.hash.SHA256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA256Test {
    @Test
    public void testSHA_256Byte() {
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, SHA256.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_256String() {
        String hexRes = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        Assertions.assertEquals(hexRes, SHA256.hash("test").getHex());
    }
}
