package hash;

import com.ltonetwork.seasalt.hash.SHA1;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA1Test {

    @Test
    public void testSHA1Byte() {
        String hexRes = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        Assertions.assertEquals(hexRes, SHA1.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA1String() {
        String hexRes = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
        Assertions.assertEquals(hexRes, SHA1.hash("test").getHex());
    }
}
