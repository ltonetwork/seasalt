package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Blake2b512;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Blake2b512Test {
    @Test
    public void testBlake2b_512Byte() {
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Blake2b512.hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_512String() {
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Blake2b512.hash("test").getHex());
    }

    @Test
    public void testBlake2b_512Binary() {
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Blake2b512.hash(new Binary("test".getBytes())).getHex());
    }
}
