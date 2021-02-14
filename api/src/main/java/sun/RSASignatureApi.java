package sun;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import util.RSAUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA - 数字签名
 * @author YangHui
 * @date 2021-02-13 19:38
 */
public class RSASignatureApi {

    public static final String KEY_ALGORITHM = "RSA";

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
        byte[] sign = RSAUtils.sign(data.getBytes(), privateKeyEncoded);
        System.out.println("私钥长度:"+KEY_SIZE+";签名长度:"+sign.length * 8);
        System.out.println("签名:"+ Hex.encodeHexString(sign));
        boolean verify = RSAUtils.verify(data.getBytes(), sign, publicKeyEncoded);
        System.out.println("签名验证结果:"+verify);
    }
}
