package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Blake2b256;
import com.ltonetwork.seasalt.hash.SHA256;
import edu.umd.cs.mtc.MultithreadedTestCase;
import edu.umd.cs.mtc.TestFramework;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ThreadingTest extends MultithreadedTestCase {
    public void thread1() {
        String hexRes = "362e25dde23febfd93264114ae0594f0c64596e9665e302ae2e1c631cf6cce19";
        Assertions.assertEquals(
                hexRes,
                Blake2b256.hash(new Binary("threading_1".getBytes())).getHex()
        );
    }
    public void thread2() {
        String hexRes = "f62fe450753da993b38492be72fc60dbc9846aaf348eaae5cf8c813e83ed17ce";
        Assertions.assertEquals(
                hexRes,
                Blake2b256.hash(new Binary("threading_2".getBytes())).getHex()
        );
    }

    public void thread3() {
        String hexRes = "21e0b81f01f004c51bee8954c15244efd78c88015d7d1b639f7f974cd85c45da";
        Assertions.assertEquals(
                hexRes,
                SHA256.hash(new Binary("threading_3".getBytes())).getHex()
        );
    }

    @Test
    public void testCounter() throws Throwable {
        TestFramework.runManyTimes(new ThreadingTest(), 100);
    }
}
