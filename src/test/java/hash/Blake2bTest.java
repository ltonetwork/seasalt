package hash;

import com.ltonetwork.seasalt.hash.Blake2b;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Blake2bTest {

    @Test
    public void testBlake2b_256Byte() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b.blake2b256Hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_256String() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b.blake2b256Hash("test").getHex());
    }

    @Test
    public void testBlake2b_384Byte() {
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Blake2b.blake2b384Hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_384String() {
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Blake2b.blake2b384Hash("test").getHex());
    }

    @Test
    public void testBlake2b_512Byte() {
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Blake2b.blake2b512Hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_512String() {
        String hexRes = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa9bc33b582f77d30a65e6f29a896c0411f38312e1d66e0bf16386c86a89bea572";
        Assertions.assertEquals(hexRes, Blake2b.blake2b512Hash("test").getHex());
    }
}
