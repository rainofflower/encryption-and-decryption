package sun;

import org.junit.Assert;
import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;

/**
 * @author YangHui
 */
public class SignatureApi {

    /**
     * 数字签名处理
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    @Test
    public void test01() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        //待做数字签名的原始信息
        byte[] data = "data signature".getBytes();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        //生成KeyPair对象
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Signature signature = Signature.getInstance(keyPairGenerator.getAlgorithm());
        //签名操作初始化
        signature.initSign(keyPair.getPrivate());
        //更新
        signature.update(data);
        //签名
        byte[] sign = signature.sign();
        //验证操作初始化
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        //验证
        boolean status = signature.verify(sign);
        Assert.assertTrue(status);
    }

    @Test
    public void test02() throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
        //待做数字签名的原始信息
        byte[] data = "data signature".getBytes();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        //生成KeyPair对象
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Signature signature = Signature.getInstance(keyPairGenerator.getAlgorithm());
        SignedObject s = new SignedObject(data, keyPair.getPrivate(), signature);
//        byte[] sign = s.getSignature();
        boolean status = s.verify(keyPair.getPublic(), signature);
        Assert.assertTrue(status);
    }

    @Test
    public void test03() throws CertificateException, FileNotFoundException {
        CertificateFactory cf = CertificateFactory.getInstance("X509");
        CertPath certPath = cf.generateCertPath(new FileInputStream("F:\\server\\resource\\x.cer"));
        Timestamp timestamp = new Timestamp(new Date(), certPath);
    }
}
