package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.SHA3512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA3512Test {
    @Test
    public void testSHA3_512Byte() {
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, SHA3512.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_512String() {
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, SHA3512.hash("test").getHex());
    }

    @Test
    public void testSHA3_512Binary() {
        String hexRes = "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14";
        Assertions.assertEquals(hexRes, SHA3512.hash(new Binary("test".getBytes())).getHex());
    }
}
