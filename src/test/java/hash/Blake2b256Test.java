package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Blake2b256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Blake2b256Test {
    @Test
    public void testBlake2b_256Byte() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_256String() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash("test").getHex());
    }

    @Test
    public void testBlake2b_256Binary() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash(new Binary("test".getBytes())).getHex());
    }
}
