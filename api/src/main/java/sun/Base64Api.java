package sun;

import org.apache.commons.codec.binary.Base64;
import org.junit.Test;

import java.io.UnsupportedEncodingException;

/**
 * Base64
 *
 * @author yanghui
 * @date 2021-02-05
 **/
public class Base64Api {

    public static final String ENCODING = "UTF-8";

    @Test
    public void test01() throws UnsupportedEncodingException {
        String s = "这是一封测试邮件！";
        byte[] encodeBytes = Base64.encodeBase64(s.getBytes());
        String encodeStr = new String(encodeBytes, ENCODING);
        System.out.println("编码后:"+encodeStr);
        byte[] decodeBytes = Base64.decodeBase64(encodeStr);
        String decodeStr = new String(decodeBytes, ENCODING);
        System.out.println("解码后:"+decodeStr);
    }

    @Test
    public void test02() throws UnsupportedEncodingException {
        String s = "这是一封测试邮件！";
        byte[] encodeBytes = Base64.encodeBase64URLSafe(s.getBytes());
        String encodeStr = new String(encodeBytes, ENCODING);
        System.out.println("编码后:"+encodeStr);
        byte[] decodeBytes = Base64.decodeBase64(encodeStr);
        String decodeStr = new String(decodeBytes, ENCODING);
        System.out.println("解码后:"+decodeStr);
    }
}
