package sun;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
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
 * DH - 密钥交换算法
 * @author YangHui
 */
public class DHApi {

    public static final String ASYMMETRIC_ALGORITHM = "DH";


    public static final String SYMMETRIC_ALGORITHM = "AES";

    private static final int KEY_SIZE = 1024;

    @Before
    public final void init(){
        /**
         *  jdk 161版本之后，不设置以下系统变量会报错：
         *  java.security.NoSuchAlgorithmException: Unsupported secret key algorithm: AES
         *  由于JDK版本不同，在Java 8 update 161版本以后就会出现此问题，
         *  根本原因还是DH密钥长度至少为512位，而AES算法密钥没有这么长，密钥长度不一致引起的。
         *  解决办法
         *  1、添加代码修改系统变量
         *  2、配置jvm系统变量 -Djdk.crypto.KeyAgreement.legacyKDF=true
         */
        System.setProperty("jdk.crypto.KeyAgreement.legacyKDF", "true");
    }

    @Test
    public void test() throws Exception{
        //先生成甲方公钥、私钥
        KeyPair keyPair = generateKeyPair();
        //甲方公钥
        PublicKey aPublic = keyPair.getPublic();
        //甲方私钥
        PrivateKey aPrivate = keyPair.getPrivate();
        byte[] aPublicKeyEncoded = aPublic.getEncoded();
        byte[] aPrivateEncoded = aPrivate.getEncoded();
        System.out.println("甲方公钥:"+Base64.encodeBase64String(aPublicKeyEncoded));
        System.out.println("甲方私钥:"+Base64.encodeBase64String(aPrivateEncoded));

        //乙方通甲方公钥 生成乙方公钥、私钥
        KeyPair keyPair2 = generateKeyPair(aPublicKeyEncoded);
        PublicKey aPublic2 = keyPair2.getPublic();
        PrivateKey aPrivate2 = keyPair2.getPrivate();
        byte[] aPublicKey2Encoded = aPublic2.getEncoded();
        byte[] aPrivate2Encoded = aPrivate2.getEncoded();
        System.out.println("乙方公钥:"+Base64.encodeBase64String(aPublicKey2Encoded));
        System.out.println("乙方私钥:"+Base64.encodeBase64String(aPrivate2Encoded));

        //双方使用对方的公钥和自己的私钥，分别生成对称密钥
        //乙方生成对称密钥
        SecretKey secretKey2 = generateSecretKey(aPrivate2Encoded, aPublicKeyEncoded);

        //甲方生成对称密钥
        SecretKey secretKey = generateSecretKey(aPrivateEncoded, aPublicKey2Encoded);
        byte[] encoded1 = secretKey.getEncoded();
        byte[] encoded2 = secretKey2.getEncoded();
        System.out.println("甲方密钥:"+ Base64.encodeBase64String(encoded1));
        System.out.println("乙方密钥:"+ Base64.encodeBase64String(encoded2));
        System.out.println("======甲 to 乙=======");
        String data = "甲 to 乙 - Cipher Data";
        System.out.println("原数据:"+data);
        System.out.println("原数据Base64:"+Base64.encodeBase64String(data.getBytes()));
        Cipher cipher = Cipher.getInstance(SYMMETRIC_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] bytes = cipher.doFinal(data.getBytes());
        System.out.println("甲方加密后:"+Base64.encodeBase64String(bytes));
        cipher.init(Cipher.DECRYPT_MODE, secretKey2);
        byte[] bytes1 = cipher.doFinal(bytes);
        String backStr = new String(bytes1);
        System.out.println("乙方解密后:"+backStr);
        Assert.assertEquals(backStr, data);

        System.out.println("======乙 to 甲=======");
        String data2 = "乙 to 甲 - Cipher Data";
        System.out.println("原数据:"+data2);
        System.out.println("原数据Base64:"+Base64.encodeBase64String(data2.getBytes()));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey2);
        byte[] bytes2 = cipher.doFinal(data2.getBytes());
        System.out.println("乙方加密后:"+Base64.encodeBase64String(bytes2));
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] bytes3 = cipher.doFinal(bytes2);
        String backStr2 = new String(bytes3);
        System.out.println("甲方解密后:"+backStr2);
        Assert.assertEquals(backStr2, data2);

    }


    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public KeyPair generateKeyPair(byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        //解析公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM);
        //还原公钥
        PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
        DHParameterSpec dhParameterSpec = ((DHPublicKey) pubKey).getParams();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
        keyPairGenerator.initialize(dhParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public SecretKey generateSecretKey(byte[] privateKey, byte[] publicKey) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ASYMMETRIC_ALGORITHM);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
        KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
        //初始化
        keyAgreement.init(priKey);
        keyAgreement.doPhase(pubKey, true);
        //生成本地密钥
        SecretKey secretKey = keyAgreement.generateSecret(SYMMETRIC_ALGORITHM);
        return secretKey;
    }
}
