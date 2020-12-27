package sun;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

/**
 * DES和AES算法提供者依赖于外部实现（jdk未实现），因此需要加入外部实现
 * 这里使用 bouncycastle 的实现，添加maven依赖后，还需在jre的java.security中加入
 * security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider
 *
 * PrivateKey
 * PublicKey
 * SecretKey
 * KeyPair
 * @author YangHui
 */
public class KeyApi {

    @Test
    public void test01() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        //生成KeyPair对象
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        //获得私钥字节数组。实际使用过程中该密钥以此种形式保存传递给另一方
        byte[] keyBytes = aPrivate.getEncoded();

        //由私钥字节数组获得密钥规范
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        //密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(keyPairGenerator.getAlgorithm());
        //生成私钥
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        System.out.println(Arrays.equals(keyBytes, privateKey.getEncoded()));
//        Assert.assertArrayEquals(keyBytes, privateKey.getEncoded());
    }

    /**
     * 构建安全随机数对象以及秘密密钥对象
     * @throws NoSuchAlgorithmException
     */
    @Test
    public void test02() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        //初始化 KeyGenerator
        keyGenerator.init(secureRandom);
        //生成 SecretKey
        SecretKey secretKey = keyGenerator.generateKey();
        //密钥编码字节数组
        byte[] keyEncoded = secretKey.getEncoded();
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyGenerator.getAlgorithm());
        DESKeySpec keySpec = new DESKeySpec(keyEncoded);
        SecretKey key = keyFactory.generateSecret(keySpec);

    }


    /**
     * AlgorithmParameterGenerator
     * AlgorithmParameters
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    @Test
    public void test() throws NoSuchAlgorithmException, IOException {
        //指定DES算法实例化AlgorithmParameterGenerator对象
        AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("DES");
        //初始化
        parameterGenerator.init(56);
        //生成AlgorithmParameters对象
        AlgorithmParameters algorithmParameters = parameterGenerator.generateParameters();
        //获取参数字节数组
        byte[] encoded = algorithmParameters.getEncoded();
        System.out.println(new BigInteger(encoded).toString());
    }

    @Test
    public void keyPairTest() throws NoSuchAlgorithmException {
        //KeyPair
        //实例化KeyPairGenerator对象
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        //初始化
        keyPairGenerator.initialize(1024);
        //生成KeyPair对象
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey aPrivate = keyPair.getPrivate();
        PublicKey aPublic = keyPair.getPublic();
        System.out.println(keyPair);
        System.out.println(aPrivate);
        System.out.println(aPublic);
    }
}
