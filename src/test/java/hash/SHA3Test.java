package hash;

import com.ltonetwork.seasalt.hash.SHA3;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA3Test {

    @Test
    public void testSHA3_256Byte() {
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, SHA3.SHA3256Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_256String() {
        String hexRes = "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80";
        Assertions.assertEquals(hexRes, SHA3.SHA3256Hash("test").getHex());
    }

    @Test
    public void testSHA3_384Byte() {
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, SHA3.SHA3384Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_384String() {
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, SHA3.SHA3384Hash("test").getHex());
    }

    @Test
    public void testSHA3_512Byte() {
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, SHA3.SHA3512Hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_512String() {
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, SHA3.SHA3512Hash("test").getHex());
    }
}
