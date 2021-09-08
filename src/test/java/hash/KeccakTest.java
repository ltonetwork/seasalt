package hash;

import com.ltonetwork.seasalt.hash.Keccak;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class KeccakTest {

    @Test
    public void testKeccak_256Byte() {
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Keccak.keccak256Hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_256String() {
        String hexRes = "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658";
        Assertions.assertEquals(hexRes, Keccak.keccak256Hash("test").getHex());
    }

    @Test
    public void testKeccak_384Byte() {
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Keccak.keccak384Hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_384String() {
        String hexRes = "53d0ba137307d4c2f9b6674c83edbd58b70c0f4340133ed0adc6fba1d2478a6a03b7788229e775d2de8ae8c0759d0527";
        Assertions.assertEquals(hexRes, Keccak.keccak384Hash("test").getHex());
    }

    @Test
    public void testKeccak_512Byte() {
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Keccak.keccak512Hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_512String() {
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Keccak.keccak512Hash("test").getHex());
    }
}
