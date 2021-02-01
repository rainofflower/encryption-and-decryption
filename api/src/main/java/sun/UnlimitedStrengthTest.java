package sun;

import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * 出口限制（密钥长度限制）测试
 * 若受限，会抛出异常 java.security.InvalidKeyException: Illegal key size
 *
 * 1、
 * 若 jdk < 1.8.151
 * 去oracle官方下载，JCE无限制文件
 * 替换本地环境JDK以及JRE
 * 将local_policy.jar 以及US_export_policy.jar俩个文件覆盖本地{JDK_HOME}/jre/lib/security和{JRE_HOME}/lib/security这个俩个文件里面的同名文件。
 * 重启jvm应用
 *
 * 2、
 * 若 1.8.151 =< jdk < 1.8.161
 * 3.2.1 修改security文件
 * 当前版本为JVM启用无限制强度管辖策略，默认不启用。如果不启用此功能，则不能使用AES-256：文件夹位于{JDK_HOME}/jre/lib/security 和{JRE_HOME}/lib/security。
 * 修改java.security文件
 * 打开 java.security文件，搜索crypto.policy这一行。 默认值为limited,将其修改为非限制，如下。
 * crypto.policy=unlimited
 * 重启jvm应用
 *
 * 3、
 * 若 1.8.0_161 =< jdk
 * 不再限制密钥长度,所以也不会出现当前这个问题
 *
 * @author yanghui
 * @date 2021-02-01
 **/
public class UnlimitedStrengthTest {

    @Test
    public void testUnlimit() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();
        System.out.println(secretKey);
        byte[] encoded = secretKey.getEncoded();
    }
}
