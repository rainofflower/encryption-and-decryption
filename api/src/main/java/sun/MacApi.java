package sun;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * 安全消息摘要算法/消息认证码(Message Authentication Code, Mac)
 * @author YangHui
 */
public class MacApi {

    @Test
    public void test01() throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] input = "MAC".getBytes();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
        SecretKey secretKey = keyGenerator.generateKey();
        //构建Mac对象
        Mac mac = Mac.getInstance(keyGenerator.getAlgorithm());
        mac.init(secretKey);
        //获取经过安全信息摘要后的信息
        byte[] output = mac.doFinal(input);
    }
}
