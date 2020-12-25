package sun;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author YangHui
 */
public class DigestOutputStreamApi {


    @Test
    public void test() throws NoSuchAlgorithmException, IOException {
        byte[] input = "md5".getBytes();
        MessageDigest digest = MessageDigest.getInstance("md5");
        DigestOutputStream digestOutputStream = new DigestOutputStream(new ByteArrayOutputStream(), digest);
        digestOutputStream.write(input, 0 , input.length);
        //获取摘要信息
        byte[] output = digest.digest();
        //清空流
        digestOutputStream.flush();
        //关闭流
        digestOutputStream.close();

    }
}
