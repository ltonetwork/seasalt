package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Keccak384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Keccak384Test {
    @Test
    public void testKeccak_384Byte() {
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Keccak384.hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_384String() {
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Keccak384.hash("test").getHex());
    }

    @Test
    public void testKeccak_384Binary() {
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Keccak384.hash(new Binary("test".getBytes())).getHex());
    }
}
