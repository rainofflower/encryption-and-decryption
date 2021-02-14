package sun;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;
import util.AESUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES
 * @author YangHui
 */
public class AESApi {

    @Test
    public void test() throws Exception {
        int maxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
        System.out.println("最大密钥长度:"+maxKeyLength);
        String data = "AES";
        System.out.println("原文:"+data);
        SecretKey secretKey = AESUtils.generateKey();
        byte[] keyEncoded = secretKey.getEncoded();
        String base64Key = Base64.encodeBase64String(keyEncoded);
        System.out.println("密钥:"+base64Key);
        //加密
        byte[] cipherBytes = AESUtils.encrypt(data.getBytes(), keyEncoded);
        System.out.println("加密后:"+Base64.encodeBase64String(cipherBytes));
        byte[] decodeBase64Key = Base64.decodeBase64(base64Key);
        //还原密钥
        SecretKey key = new SecretKeySpec(decodeBase64Key, AESUtils.KEY_ALGORITHM);
        //解密
        byte[] plainBytes = AESUtils.decrypt(cipherBytes, key.getEncoded());
        String plainText = new String(plainBytes);
        System.out.println("解密后:"+plainText);
        Assert.assertEquals(plainText, data);
    }


}
