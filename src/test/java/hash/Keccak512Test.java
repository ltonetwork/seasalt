package hash;

import com.ltonetwork.seasalt.hash.Keccak512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Keccak512Test {
    @Test
    public void testKeccak_512Byte() {
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Keccak512.hash("test".getBytes()).getHex());
    }

    @Test
    public void testKeccak_512String() {
        String hexRes = "1e2e9fc2002b002d75198b7503210c05a1baac4560916a3c6d93bcce3a50d7f00fd395bf1647b9abb8d1afcc9c76c289b0c9383ba386a956da4b38934417789e";
        Assertions.assertEquals(hexRes, Keccak512.hash("test").getHex());
    }
}
