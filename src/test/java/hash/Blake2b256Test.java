package hash;

import com.ltonetwork.seasalt.Binary;
import com.ltonetwork.seasalt.hash.Blake2b256;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class Blake2b256Test {
    @Test
    public void testBlake2b_256Byte() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash("test".getBytes()).getHex());
    }

    @Test
    public void testBlake2b_256String() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash("test").getHex());
    }

    @Test
    public void testBlake2b_256Binary() {
        String hexRes = "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202";
        Assertions.assertEquals(hexRes, Blake2b256.hash(new Binary("test".getBytes())).getHex());
    }

    @Test
    public void testBlake2b_256_multithread() {
        Runnable task_1 = () -> {
            String hexRes = "7ba3f3325eb69d507a7d7feb08297b36798c12245ebd6527d78099e94dac8bdd";
            Assertions.assertEquals(hexRes, Blake2b256.hash(new Binary("task_1".getBytes())).getHex());
        };

        Runnable task_2 = () -> {
            String hexRes = "43600450cff431c84c6a28e614aa708c7899ccad1aa4ed472bccd99de4e537bb";
            Assertions.assertEquals(hexRes, Blake2b256.hash(new Binary("task_2".getBytes())).getHex());
        };

        Runnable task_3 = () -> {
            String hexRes = "f0259052aaca82ed016a69603ce020de190632b64643b5bcacbd47c813054b22";
            Assertions.assertEquals(hexRes, Blake2b256.hash(new Binary("task_3".getBytes())).getHex());
        };

        Thread thread_1 = new Thread(task_1);
        Thread thread_2 = new Thread(task_2);
        Thread thread_3 = new Thread(task_3);

        thread_1.start();
        thread_2.start();
        thread_3.start();
    }
}
