package sun;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.junit.Assert;
import org.junit.Test;
import util.AESUtils;
import util.KeyUtils;
import util.RSAUtils;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA算法
 * -加解密
 * -数字签名
 * @author YangHui
 * @date 2021-02-12 19:28
 */
public class RSAApi {

    /**
     * RSA加解密数据
     * @throws Exception
     */
    @Test
    public void test() throws Exception{
        KeyPair keyPair = RSAUtils.generateKey();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        System.out.println("公钥:"+ Base64.encodeBase64String(publicKeyEncoded));
        System.out.println("私钥:"+Base64.encodeBase64String(privateKeyEncoded));
        //假设乙生成公私钥，并将公钥公布给甲
        System.out.println("===甲 to 乙===");
        String data1 = "账号xxx";
        System.out.println("原数据:"+data1);
        byte[] encryptByPublicKey = RSAUtils.encryptByPublicKey(data1.getBytes(), publicKeyEncoded);
        System.out.println("加密后:"+Base64.encodeBase64String(encryptByPublicKey));
        byte[] decryptByPrivateKey = RSAUtils.decryptByPrivateKey(encryptByPublicKey, privateKeyEncoded);
        String decrypt1 = new String(decryptByPrivateKey);
        System.out.println("解密后:"+decrypt1);

        System.out.println("===乙 to 甲===");
        String data2 = "got it";
        System.out.println("原数据:"+data2);
        byte[] encryptByPrivateKey2 = RSAUtils.encryptByPrivateKey(data2.getBytes(), privateKeyEncoded);
        System.out.println("加密后:"+Base64.encodeBase64String(encryptByPrivateKey2));
        byte[] decryptByPrivateKey2 = RSAUtils.decryptByPublicKey(encryptByPrivateKey2, publicKeyEncoded);
        String decrypt2 = new String(decryptByPrivateKey2);
        System.out.println("解密后:"+decrypt2);
    }

    /**
     * RSA签名、RSA、AES加解密结合运用
     *
     * 1、假设乙生成公私钥，并将公钥公布给甲
     *
     * 2、甲生成后续数据加密用的密钥，通过RSA算法使用乙公布的公钥加密密钥，发送给乙
     *
     * 3、乙通过RSA算法使用私钥解密甲发送过来的密钥，得到数据加密用的对称密钥
     *
     * 4、乙先对向甲发送的数据做签名处理（通过私钥使用RSA算法签名），
     * 然后将得到的签名值与原数据拼接在一起（此处是将签名放在头部），
     * 再对整段数据通过对称密钥使用对称加密算法加密
     *
     * 5、甲对收到的数据先做解密处理（密钥使用AES解密），然后分别取出原数据和乙的签名值，
     * 再通过公钥使用RSA算法，以原数据、乙的签名作为参数，验证数据
     *
     * @throws Exception
     */
    @Test
    public void test2() throws Exception{
        //生成非对称加密的密钥对
        KeyPair keyPair = RSAUtils.generateKey();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        String publicKeyString = KeyUtils.getKeyHexString(publicKeyEncoded);
        String privateKeyString = KeyUtils.getKeyHexString(privateKeyEncoded);
        System.out.println("公钥:"+ publicKeyString);
        System.out.println("私钥:"+ privateKeyString);
        System.out.println("===甲用公钥使用RSA算法加密AES算法要使用到的密钥，传输给乙===");
        //生成对称加密的密钥
        SecretKey secretKey = AESUtils.generateKey();
        String secretKeyHexStr = Hex.encodeHexString(secretKey.getEncoded());
        System.out.println("甲生成的密钥:"+secretKeyHexStr);
        byte[] bytes = RSAUtils.encryptByPublicKey(secretKeyHexStr.getBytes(), KeyUtils.getKey(publicKeyString));
        System.out.println("甲使用公钥加密后的密钥:"+Hex.encodeHexString(bytes));
        byte[] key = RSAUtils.decryptByPrivateKey(bytes, KeyUtils.getKey(privateKeyString));
        String keyStr = new String(key);
        System.out.println("乙使用私钥解密后的密钥:"+keyStr);
        String data = "it's my secret";
        System.out.println("乙向甲发送的原数据:"+data);
        byte[] sign = RSAUtils.sign(data.getBytes(), KeyUtils.getKey(privateKeyString));
        String signStr = Hex.encodeHexString(sign);
        System.out.println("乙发送数据的签名:"+signStr);
        data = signStr + data;
        byte[] encryptData = AESUtils.encrypt(data.getBytes(), KeyUtils.getKey(keyStr));
        System.out.println("乙将要发送的加密后的数据:"+Hex.encodeHexString(encryptData));

        byte[] decryptData = AESUtils.decrypt(encryptData, KeyUtils.getKey(secretKeyHexStr));
        System.out.println("甲收到乙发送的数据:"+Hex.encodeHexString(decryptData));
        String receiveData = new String(decryptData);
        String signStr2 = receiveData.substring(0, RSAUtils.KEY_SIZE / 4);
        String data2 = receiveData.substring(RSAUtils.KEY_SIZE / 4);
        System.out.println("乙的签名:"+signStr2);
        System.out.println("乙发送的原始数据:"+data2);
        boolean verify = RSAUtils.verify(data2.getBytes(), Hex.decodeHex(signStr2), KeyUtils.getKey(publicKeyString));
        Assert.assertTrue(verify);

    }

}
