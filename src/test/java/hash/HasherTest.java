package hash;

import com.ltonetwork.seasalt.hash.Hasher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class HasherTest {

    @Test
    public void testSHA_256Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-256");
        byte[] byteTest = new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA_256String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-256");
        byte[] byteTest = new byte[]{-97, -122, -48, -127, -120, 76, 125, 101, -102, 47, -22, -96, -59, 90, -48, 21, -93, -65, 79, 27, 43, 11, -126, 44, -47, 93, 108, 21, -80, -16, 10, 8};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testSHA_384Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-384");
        byte[] byteTest = new byte[]{118, -124, 18, 50, 15, 123, 10, -91, -127, 47, -50, 66, -115, -60, 112, 107, 60, -82, 80, -32, 42, 100, -54, -95, 106, 120, 34, 73, -65, -24, -17, -60, -73, -17, 28, -53, 18, 98, 85, -47, -106, 4, 125, -2, -33, 23, -96, -87};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA_384String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-384");
        byte[] byteTest = new byte[]{118, -124, 18, 50, 15, 123, 10, -91, -127, 47, -50, 66, -115, -60, 112, 107, 60, -82, 80, -32, 42, 100, -54, -95, 106, 120, 34, 73, -65, -24, -17, -60, -73, -17, 28, -53, 18, 98, 85, -47, -106, 4, 125, -2, -33, 23, -96, -87};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testSHA_512Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-512");
        byte[] byteTest = new byte[]{-18, 38, -80, -35, 74, -9, -25, 73, -86, 26, -114, -29, -63, 10, -23, -110, 63, 97, -119, -128, 119, 46, 71, 63, -120, 25, -91, -44, -108, 14, 13, -78, 122, -63, -123, -8, -96, -31, -43, -8, 79, -120, -68, -120, 127, -42, 123, 20, 55, 50, -61, 4, -52, 95, -87, -83, -114, 111, 87, -11, 0, 40, -88, -1};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA_512String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA-512");
        byte[] byteTest = new byte[]{-18, 38, -80, -35, 74, -9, -25, 73, -86, 26, -114, -29, -63, 10, -23, -110, 63, 97, -119, -128, 119, 46, 71, 63, -120, 25, -91, -44, -108, 14, 13, -78, 122, -63, -123, -8, -96, -31, -43, -8, 79, -120, -68, -120, 127, -42, 123, 20, 55, 50, -61, 4, -52, 95, -87, -83, -114, 111, 87, -11, 0, 40, -88, -1};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testSHA3_256Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-256");
        byte[] byteTest = new byte[]{54, -16, 40, 88, 11, -80, 44, -56, 39, 42, -102, 2, 15, 66, 0, -29, 70, -30, 118, -82, 102, 78, 69, -18, -128, 116, 85, 116, -30, -11, -85, -128};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA3_256String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-256");
        byte[] byteTest = new byte[]{54, -16, 40, 88, 11, -80, 44, -56, 39, 42, -102, 2, 15, 66, 0, -29, 70, -30, 118, -82, 102, 78, 69, -18, -128, 116, 85, 116, -30, -11, -85, -128};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testSHA3_384Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-384");
        byte[] byteTest = new byte[]{-27, 22, -38, -69, 35, -74, -29, 0, 38, -122, 53, 67, 40, 39, -128, -93, -82, 13, -52, -16, 85, 81, -49, 2, -107, 23, -115, 127, -16, -15, -76, 30, -20, -71, -37, 63, -14, 25, 0, 124, 78, 9, 114, 96, -43, -122, 33, -67};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA3_384String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-384");
        byte[] byteTest = new byte[]{-27, 22, -38, -69, 35, -74, -29, 0, 38, -122, 53, 67, 40, 39, -128, -93, -82, 13, -52, -16, 85, 81, -49, 2, -107, 23, -115, 127, -16, -15, -76, 30, -20, -71, -37, 63, -14, 25, 0, 124, 78, 9, 114, 96, -43, -122, 33, -67};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testSHA3_512Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-512");
        byte[] byteTest = new byte[]{-98, -50, 8, 110, -101, -84, 73, 31, -84, 92, 29, 16, 70, -54, 17, -41, 55, -71, 42, 43, 46, -67, -109, -16, 5, -41, -73, 16, 17, 12, 10, 103, -126, -120, 22, 110, 127, -66, 121, 104, -125, -92, -14, -23, -77, -54, -97, 72, 79, 82, 29, 12, -28, 100, 52, 92, -63, -82, -55, 103, 121, 20, -100, 20};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testSHA3_512String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("SHA3-512");
        byte[] byteTest = new byte[]{-98, -50, 8, 110, -101, -84, 73, 31, -84, 92, 29, 16, 70, -54, 17, -41, 55, -71, 42, 43, 46, -67, -109, -16, 5, -41, -73, 16, 17, 12, 10, 103, -126, -120, 22, 110, 127, -66, 121, 104, -125, -92, -14, -23, -77, -54, -97, 72, 79, 82, 29, 12, -28, 100, 52, 92, -63, -82, -55, 103, 121, 20, -100, 20};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testBlake2b_256Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-256");
        byte[] byteTest = new byte[]{-110, -117, 32, 54, 105, 67, -30, -81, -47, 30, -68, 14, -82, 46, 83, -87, 59, -15, 119, -92, -4, -13, 91, -52, 100, -43, 3, 112, 78, 101, -30, 2};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testBlake2b_256String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-256");
        byte[] byteTest = new byte[]{-110, -117, 32, 54, 105, 67, -30, -81, -47, 30, -68, 14, -82, 46, 83, -87, 59, -15, 119, -92, -4, -13, 91, -52, 100, -43, 3, 112, 78, 101, -30, 2};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testBlake2b_384Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-384");
        byte[] byteTest = new byte[]{-118, -124, -72, 102, 108, -113, -49, -74, -97, 46, -60, 31, 87, -115, 124, -123, -5, -37, 80, 78, -90, 81, 15, -80, 91, 80, -4, -65, 126, -40, 21, 60, 119, -108, 59, -62, -38, 115, -85, -79, 54, -125, 78, 26, 13, 79, 34, -53};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testBlake2b_384String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-384");
        byte[] byteTest = new byte[]{-118, -124, -72, 102, 108, -113, -49, -74, -97, 46, -60, 31, 87, -115, 124, -123, -5, -37, 80, 78, -90, 81, 15, -80, 91, 80, -4, -65, 126, -40, 21, 60, 119, -108, 59, -62, -38, 115, -85, -79, 54, -125, 78, 26, 13, 79, 34, -53};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testBlake2b_512Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-512");
        byte[] byteTest = new byte[]{-89, 16, 121, -44, 40, 83, -34, -94, 110, 69, 48, 4, 51, -122, 112, -91, 56, 20, -73, -127, 55, -1, -66, -48, 118, 3, -92, 29, 118, -92, -125, -86, -101, -61, 59, 88, 47, 119, -45, 10, 101, -26, -14, -102, -119, 108, 4, 17, -13, -125, 18, -31, -42, 110, 11, -15, 99, -122, -56, 106, -119, -66, -91, 114};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testBlake2b_512String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Blake2b-512");
        byte[] byteTest = new byte[]{-89, 16, 121, -44, 40, 83, -34, -94, 110, 69, 48, 4, 51, -122, 112, -91, 56, 20, -73, -127, 55, -1, -66, -48, 118, 3, -92, 29, 118, -92, -125, -86, -101, -61, 59, 88, 47, 119, -45, 10, 101, -26, -14, -102, -119, 108, 4, 17, -13, -125, 18, -31, -42, 110, 11, -15, 99, -122, -56, 106, -119, -66, -91, 114};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testKeccak_256Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-256");
        byte[] byteTest = new byte[]{-100, 34, -1, 95, 33, -16, -72, 27, 17, 62, 99, -9, -37, 109, -87, 79, -19, -17, 17, -78, 17, -101, 64, -120, -72, -106, 100, -5, -102, 60, -74, 88};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testKeccak_256String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-256");
        byte[] byteTest = new byte[]{-100, 34, -1, 95, 33, -16, -72, 27, 17, 62, 99, -9, -37, 109, -87, 79, -19, -17, 17, -78, 17, -101, 64, -120, -72, -106, 100, -5, -102, 60, -74, 88};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testKeccak_384Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-384");
        byte[] byteTest = new byte[]{83, -48, -70, 19, 115, 7, -44, -62, -7, -74, 103, 76, -125, -19, -67, 88, -73, 12, 15, 67, 64, 19, 62, -48, -83, -58, -5, -95, -46, 71, -118, 106, 3, -73, 120, -126, 41, -25, 117, -46, -34, -118, -24, -64, 117, -99, 5, 39};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testKeccak_384String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-384");
        byte[] byteTest = new byte[]{83, -48, -70, 19, 115, 7, -44, -62, -7, -74, 103, 76, -125, -19, -67, 88, -73, 12, 15, 67, 64, 19, 62, -48, -83, -58, -5, -95, -46, 71, -118, 106, 3, -73, 120, -126, 41, -25, 117, -46, -34, -118, -24, -64, 117, -99, 5, 39};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }

    @Test
    public void testKeccak_512Byte() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-512");
        byte[] byteTest = new byte[]{30, 46, -97, -62, 0, 43, 0, 45, 117, 25, -117, 117, 3, 33, 12, 5, -95, -70, -84, 69, 96, -111, 106, 60, 109, -109, -68, -50, 58, 80, -41, -16, 15, -45, -107, -65, 22, 71, -71, -85, -72, -47, -81, -52, -100, 118, -62, -119, -80, -55, 56, 59, -93, -122, -87, 86, -38, 75, 56, -109, 68, 23, 120, -98};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test".getBytes()).getBinary());
    }

    @Test
    public void testKeccak_512String() throws NoSuchAlgorithmException, NoSuchProviderException {
        Hasher hasher = new Hasher("Keccak-512");
        byte[] byteTest = new byte[]{30, 46, -97, -62, 0, 43, 0, 45, 117, 25, -117, 117, 3, 33, 12, 5, -95, -70, -84, 69, 96, -111, 106, 60, 109, -109, -68, -50, 58, 80, -41, -16, 15, -45, -107, -65, 22, 71, -71, -85, -72, -47, -81, -52, -100, 118, -62, -119, -80, -55, 56, 59, -93, -122, -87, 86, -38, 75, 56, -109, 68, 23, 120, -98};
        Assertions.assertArrayEquals(byteTest, hasher.hash("test").getBinary());
    }
}
