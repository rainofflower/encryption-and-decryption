package sun;

import org.junit.Test;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * 证书
 * 密钥库
 * @author YangHui
 */
public class CertApi {

    @Test
    public void test1() throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream("F:\\server\\resource\\x.keystore");
        //获取证书
        Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
        fileInputStream.close();

    }

    @Test
    public void test2() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
        FileInputStream fileInputStream = new FileInputStream("F:\\server\\resource\\x.keystore");
        KeyStore keyStore = KeyStore.getInstance("JKS");
        //加载密钥库
        keyStore.load(fileInputStream, "password".toCharArray());
        fileInputStream.close();
        //获取证书
        X509Certificate x509Certificate = (X509Certificate) keyStore.getCertificate("alias");
        //通过证书标明的签名算法构建 Signature 对象
        Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());

    }
}
