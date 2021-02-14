package util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;

/**
 * @author YangHui
 * @date 2021-02-14 11:15
 */
public class AESUtils {

    public static final String KEY_ALGORITHM = "AES";

    /**
     * java7不支持 AES PKCS7Padding填充方式，需要依赖BouncyCastle实现
     */
    public static final String CIPHER_ALGORITHM = "AES/ECB/PKCS7Padding";

    public static final int KEY_SIZE = 256;

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        //注意若1.8.0_161 =< jdk 密钥长度有出口限制（最大不超过128位），需要下载限制文件，覆盖原文件
        keyGenerator.init(KEY_SIZE);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    /**
     * 加密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception{
        //加入 BouncyCastleProvider 支持
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    /**
     * 解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        SecretKey secretKey = new SecretKeySpec(key, KEY_ALGORITHM);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }



}
