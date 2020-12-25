package sun;

import org.junit.Assert;
import org.junit.Test;

import java.io.*;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author YangHui
 */
public class DigestInputStreamApi {

    @Test
    public void test() throws NoSuchAlgorithmException, IOException {
        File file = new File("F:\\server\\resource\\digestStream.txt");
        MessageDigest md = MessageDigest.getInstance("MD5");
        //文件流
        DigestInputStream digestInputStream = new DigestInputStream(new FileInputStream(file), md);
        //读取文件内容并更新摘要
        while(digestInputStream.read() != -1);
        //获取摘要
        byte[] output = md.digest();
        digestInputStream.close();

        byte[] input = "md5".getBytes();
        //字符流
        DigestInputStream digestInputStream2 = new DigestInputStream(new ByteArrayInputStream(input), md);
        digestInputStream2.read(input);
        byte[] output2 = md.digest();
        digestInputStream2.close();
        Assert.assertTrue(MessageDigest.isEqual(output, output2));
    }


}
