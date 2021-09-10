package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.SHA3256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA3256Test {
    @Test
    public void testSHA3_256Byte() {
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, SHA3256.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_256String() {
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, SHA3256.hash("test").getHex());
    }

    @Test
    public void testSHA3_256Binary() {
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, SHA3256.hash(new Binary("test".getBytes())).getHex());
    }
}
