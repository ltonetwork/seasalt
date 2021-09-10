package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Blake2b384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Blake2b384Test {
    @Test
    public void testBlake2b_384Byte() {
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Blake2b384.hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_384String() {
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Blake2b384.hash("test").getHex());
    }

    @Test
    public void testBlake2b_384Binary() {
        String hexRes = "8a84b8666c8fcfb69f2ec41f578d7c85fbdb504ea6510fb05b50fcbf7ed8153c77943bc2da73abb136834e1a0d4f22cb";
        Assertions.assertEquals(hexRes, Blake2b384.hash(new Binary("test".getBytes())).getHex());
    }
}
