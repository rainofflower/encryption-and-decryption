package sun;

import org.junit.Test;
import util.SecurityUtils;

import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.cert.Certificate;

/**
 * SSL 安全套接字
 * HTTPS
 * @author YangHui
 */
public class SSLApi {

    public static final int PORT = 1443;

    static{
        //输出当前网络下的debug日志
        System.setProperty("javax.net.debug","all");
    }

    @Test
    public void test1() throws IOException {
        SSLServerSocketFactory serverSocketFactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();
        //构建SSLServerSocket实例
        SSLServerSocket serverSocket = (SSLServerSocket)serverSocketFactory.createServerSocket(PORT);
        SSLSocket socket = (SSLSocket)serverSocket.accept();
        //
        socket.close();
    }

    /**
     * 使用默认的SSLSocketFactory构建Socket
     * 握手阶段报错 Software caused connection abort: recv failed
     * 因为默认情况下，JVM没有与SSL相关的配置，需要我们手工配置
     * @throws IOException
     */
    @Test
    public void test2() throws IOException {
        SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket)socketFactory.createSocket("localhost",PORT);
        //SSL握手
        socket.startHandshake();
        //获取SSLSession
        SSLSession sslSession = socket.getSession();
        socket.close();
        //获取数字证书
        Certificate[] certificates = sslSession.getPeerCertificates();
    }

    /**
     * 通过KeyManagerFactory、TrustManagerFactory配置获取SSLServerSocketFactory
     * @throws Exception
     */
    @Test
    public void test3() throws Exception {
        String keyStorePath = "";
        String trustKeyStorePath = "";
        String password = "";
        SSLServerSocketFactory sslServerSocketFactory = SecurityUtils.getSSLServerSocketFactory(keyStorePath, trustKeyStorePath, password);
        //构建SSLServerSocket实例
        SSLServerSocket serverSocket = (SSLServerSocket)sslServerSocketFactory.createServerSocket(PORT);
        SSLSocket socket = (SSLSocket)serverSocket.accept();
        //
        socket.close();
    }

    @Test
    public void test4() throws Exception {
        String keyStorePath = "";
        String trustKeyStorePath = "";
        String password = "";
        SSLSocketFactory sslSocketFactory = SecurityUtils.getSSLSocketFactory(keyStorePath, trustKeyStorePath, password);
        SSLSocket socket = (SSLSocket)sslSocketFactory.createSocket("localhost",PORT);
        //SSL握手
        socket.startHandshake();
        //获取SSLSession
        SSLSession sslSession = socket.getSession();
        socket.close();
        //获取数字证书
        Certificate[] certificates = sslSession.getPeerCertificates();
    }

}
