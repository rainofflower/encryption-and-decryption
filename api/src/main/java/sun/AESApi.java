package sun;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;

/**
 * AES
 * @author YangHui
 */
public class AESApi {

    public static final String KEY_ALGORITHM = "AES";

    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    @Test
    public void test() throws Exception {
        int maxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("最大密钥长度:"+maxKeyLength);
        String data = "AES";
        System.out.println("原文:"+data);
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        //注意若1.8.0_161 =< jdk 密钥长度有出口限制（最大不超过128位），需要下载限制文件，覆盖原文件
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyEncoded = secretKey.getEncoded();
        String base64Key = Base64.encodeBase64String(keyEncoded);
        System.out.println("密钥:"+base64Key);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //加密
        byte[] cipherBytes = cipher.doFinal(data.getBytes());
        System.out.println("加密后:"+Base64.encodeBase64String(cipherBytes));
        byte[] decodeBase64Key = Base64.decodeBase64(base64Key);
        //还原密钥
        SecretKey key = new SecretKeySpec(decodeBase64Key, KEY_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        //解密
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        String plainText = new String(plainBytes);
        System.out.println("解密后:"+plainText);
        Assert.assertEquals(plainText, data);
    }
}
