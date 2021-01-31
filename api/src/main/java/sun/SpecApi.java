package sun;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 密钥规范、算法参数规范
 * @author YangHui
 */
public class SpecApi {

    /**
     * X509EncodedKeySpec 以编码格式表示公钥
     * PKCS8EncodedKeySpec 以编码格式表示私钥
     * 常用于 转换 保存在文件中的公钥/私钥二进制数组 为密钥对象
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    @Test
    public void test1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        //获取公钥密钥字节数组
        byte[] publicKeyEncoded = publicKey.getEncoded();
        //实例化X509EncodedKeySpec对象
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyEncoded);
        //密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(keyPairGenerator.getAlgorithm());
        //获取公钥对象
        PublicKey aPublic = keyFactory.generatePublic(x509EncodedKeySpec);
        System.out.println(aPublic.equals(publicKey));

        PrivateKey privateKey = keyPair.getPrivate();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyEncoded);
        //获取私钥对象
        PrivateKey aPrivate = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        System.out.println(privateKey.equals(aPrivate));
    }

    /**
     * 对称密钥还原
     * SecretKeySpec
     * DESKeySpec
     */
    @Test
    public void test2() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] keyEncoded = secretKey.getEncoded();
        SecretKey secretKey1 = new SecretKeySpec(keyEncoded, "DES");
    }
}
