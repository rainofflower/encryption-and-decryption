package sun;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

/**
 * 对象加密算法 - DES
 * @author YangHui
 */
public class DESApi {

    public static final String KEY_ALGORITHM = "DES";

    public static final String CIPHER_ALGORITHM = "DES/ECB/PKCS7Padding";

    @Test
    public void test() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        //Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(64);
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] encoded = secretKey.getEncoded();
        /**
         * 以下使用Base64编解码，主要是模拟与合作公司/银行对接时对密钥的处理
         * 一般加密算法会先和银行商定好，然后再接收对方密钥，密钥一般以Base64编码或十六进制编码
         */
        //编码密钥再编码成Base64字符串形式
        String base64Key = Base64.encodeBase64String(encoded);
        System.out.println("密钥base64编码:"+base64Key);
        String data = "DES";
        System.out.println("原文:"+data);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //加密
        byte[] cipherBytes = cipher.doFinal(data.getBytes());
        //System.out.println("密文base64编码:"+Base64.encodeBase64String(cipherBytes));
        //解码Base64编码的密钥
        byte[] decodeKeyBytes = Base64.decodeBase64(base64Key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        DESKeySpec keySpec = new DESKeySpec(decodeKeyBytes);
        SecretKey restoredKey = keyFactory.generateSecret(keySpec);
        cipher.init(Cipher.DECRYPT_MODE, restoredKey);
        //解密
        byte[] plainBytes = cipher.doFinal(cipherBytes);
        String plainText = new String(plainBytes);
        System.out.println("还原后的原文:"+plainText);
        Assert.assertEquals(data, plainText);
    }
}
