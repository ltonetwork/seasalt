package hash;

import com.ltonetwork.seasalt.hash.SHA384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA384Test {
    @Test
    public void testSHA_384Byte() {
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, SHA384.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA_384String() {
        String hexRes = "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9";
        Assertions.assertEquals(hexRes, SHA384.hash("test").getHex());
    }
}
