package sun;

import org.junit.Test;

import java.security.*;

/**
 * @author YangHui
 */
public class MessageDigestApi {

    @Test
    public void test01() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] input = "sha".getBytes();
        Provider sunRsaSign = Security.getProvider("SunRsaSign");
        MessageDigest digest = MessageDigest.getInstance("SHA");
        Provider provider = digest.getProvider();
        System.out.println(provider);
//        digest.update(input);
        byte[] output = digest.digest(input);
//        String s = new String(output);
//        System.out.println(s);
//        digest.reset();
        digest.update("sha1".getBytes());
        byte[] output2 = digest.digest();
        System.out.println(MessageDigest.isEqual(output, output2));
    }
}
