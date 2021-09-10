package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Keccak256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Keccak256Test {
    @Test
    public void testKeccak_256Byte() {
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Keccak256.hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_256String() {
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Keccak256.hash("test").getHex());
    }

    @Test
    public void testKeccak_256Binary() {
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Keccak256.hash(new Binary("test".getBytes())).getHex());
    }
}
