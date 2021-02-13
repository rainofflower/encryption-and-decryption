package sun;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * RSA - 数字签名
 * @author YangHui
 * @date 2021-02-13 19:38
 */
public class RSASignatureApi {

    public static final String KEY_ALGORITHM = "RSA";

    public static final String SIGNATURE_ALGORITHM = "SHA512withRSA";

    private static final int KEY_SIZE = 1024;

    @Test
    public void test() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        byte[] publicKeyEncoded = publicKey.getEncoded();
        byte[] privateKeyEncoded = privateKey.getEncoded();
        System.out.println("公钥:"+ Base64.encodeBase64String(publicKeyEncoded));
        System.out.println("私钥:"+Base64.encodeBase64String(privateKeyEncoded));
        String data = "signature";
        System.out.println("待签名数据:"+data);
        byte[] sign = sign(data.getBytes(), privateKeyEncoded);
        System.out.println("私钥长度:"+KEY_SIZE+";签名长度:"+sign.length * 8);
        System.out.println("签名:"+ Hex.encodeHexString(sign));
        boolean verify = verify(data.getBytes(), sign, publicKeyEncoded);
        System.out.println("签名验证结果:"+verify);
    }

    /**
     * 签名
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] sign(byte[] data, byte[] key) throws Exception{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * 校验
     * @param data
     * @param sign
     * @param key
     * @return
     * @throws Exception
     */
    public static boolean verify(byte[] data, byte[] sign, byte[] key) throws Exception{
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sign);
    }
}
