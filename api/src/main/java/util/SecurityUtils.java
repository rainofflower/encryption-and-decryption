package util;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * @author YangHui
 */
public class SecurityUtils {

    /**
     * 获取keyStore
     *
     * @param keyStorePath
     * @param password
     * @return 密钥库
     * @throws Exception
     */
    public static KeyStore getKeyStore(String keyStorePath, String password) throws Exception {
        FileInputStream in = new FileInputStream(keyStorePath);
        //实例化密钥库
        KeyStore keyStore = KeyStore.getInstance("jks");
        //加载密钥库
        keyStore.load(in, password.toCharArray());
        in.close();
        return keyStore;
    }

    /**
     * 获取SSLContext
     *
     * @param keyStorePath
     * @param trustKeyStorePath
     * @param password
     * @return
     * @throws Exception
     */
    public static SSLContext getSSLContext(String keyStorePath, String trustKeyStorePath, String password) throws Exception{
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        KeyStore keyStore = getKeyStore(keyStorePath, password);
        keyManagerFactory.init(keyStore, password.toCharArray());
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        KeyStore trustKeyStore = getKeyStore(trustKeyStorePath, password);
        trustManagerFactory.init(trustKeyStore);
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    public static SSLServerSocketFactory getSSLServerSocketFactory(String keyStorePath, String trustKeyStorePath, String password) throws Exception {
        SSLContext sslContext = getSSLContext(keyStorePath, trustKeyStorePath, password);
        return sslContext.getServerSocketFactory();
    }

    public static SSLSocketFactory getSSLSocketFactory(String keyStorePath, String trustKeyStorePath, String password) throws Exception {
        SSLContext sslContext = getSSLContext(keyStorePath, trustKeyStorePath, password);
        return sslContext.getSocketFactory();
    }
}
