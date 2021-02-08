package sun;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * 消息摘要算法--验证数据完整性
 * MessageDigest
 * DigestUtils
 * @author YangHui
 */
public class MessageDigestApi {

    /**
     * SHA-512 算法生成的摘要长度为 512bit (64byte)
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @Test
    public void test01() throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] input = "sha".getBytes();
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        Provider provider = digest.getProvider();
        System.out.println(provider);
//        digest.update(input);
        //更新并获取摘要
        byte[] output = digest.digest(input);
//        String s = new String(output);
//        System.out.println(s);
//        digest.reset();
        //更新摘要
        digest.update("sha".getBytes());
        //获取摘要结果
        byte[] output2 = digest.digest();
        //64byte
        System.out.println(output2.length);
        String hexString = Hex.encodeHexString(output2);
        System.out.println(hexString);
        //16进制消息摘要长度128
        System.out.println(hexString.length());
        System.out.println(MessageDigest.isEqual(output, output2));
    }

    @Test
    public void testMD5(){
        String str = "MD5Hex消息摘要";
        byte[] md5 = DigestUtils.md5(str);
        String hexString = Hex.encodeHexString(md5);
        System.out.println(hexString);
        String md5Hex = DigestUtils.md5Hex(str);
        Assert.assertEquals(md5Hex, hexString);
    }

    @Test
    public void testDigestUtils(){
        String str = "消息摘要";
        String hexString = DigestUtils.sha512Hex(str);
        System.out.println(hexString);
        Assert.assertEquals(hexString.length(), 512 / 4);
    }

    /**
     * Hmac算法 -- 带密钥的消息摘要算法
     * （密钥不同，即使算法相同，得到的摘要也不一样）
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Test
    public void testHmac() throws NoSuchAlgorithmException, InvalidKeyException {
        String str = "消息摘要";
        //甲方构建密钥
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512");
        SecretKey secretKey = keyGenerator.generateKey();
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);
        //甲方计算出的摘要
        byte[] bytes1 = mac.doFinal(str.getBytes());
        System.out.println(Hex.encodeHexString(bytes1));
        //甲方将二进制的密钥发送给乙方
        byte[] encoded = secretKey.getEncoded();
        //模拟 乙方还原甲方发送过来的密钥（具体使用的算法需双方提前协商好）
        SecretKeySpec key = new SecretKeySpec(encoded,"HmacSHA512");
        Mac mac2 = Mac.getInstance(key.getAlgorithm());
        mac2.init(key);
        //乙方用自己还原好的密钥计算出摘要
        byte[] bytes2 = mac2.doFinal(str.getBytes());
        System.out.println(Hex.encodeHexString(bytes2));
        //乙方比对甲方发送的摘要信息是否一致
        Assert.assertArrayEquals(bytes1, bytes2);
    }
}
