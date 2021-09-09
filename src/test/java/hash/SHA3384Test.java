package hash;

import com.ltonetwork.seasalt.hash.SHA3384;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SHA3384Test {
    @Test
    public void testSHA3_384Byte() {
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, SHA3384.hash("test".getBytes()).getHex());
    }

    @Test
    public void testSHA3_384String() {
        String hexRes = "e516dabb23b6e30026863543282780a3ae0dccf05551cf0295178d7ff0f1b41eecb9db3ff219007c4e097260d58621bd";
        Assertions.assertEquals(hexRes, SHA3384.hash("test").getHex());
    }
}
