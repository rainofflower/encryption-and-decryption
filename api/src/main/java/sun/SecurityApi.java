package sun;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Map;

/**
 * @author YangHui
 */
@Slf4j
public class SecurityApi {

    /**
     * 下方代码打印结果见resources/Provider-List.txt
     */
    @Test
    public void test01(){
        //遍历目前环境中的安全提供者
        Provider[] providers = Security.getProviders();
        for(Provider p : providers){
            //提供者信息
            System.out.println(p);
            for (Map.Entry<Object, Object> entry : p.entrySet()) {
                //提供者键值
                System.out.println("\t"+entry.getKey());
            }
        }
    }

    @Test
    public void test02(){
        //根据名称获取提供者
        Provider provider = Security.getProvider("SunRsaSign");
        System.out.println(provider);
        /**
         * 获取安全属性值
         * 可以设置/读取D:\Program Files\Java\jdk1.8.0_231\jre\lib\security
         * java.security文件内容
         */
        String property = Security.getProperty("security.provider.2");
        System.out.println(property);

        System.out.println("------");
        System.out.println(Security.getProperty("security.provider.1"));
        Provider sunRsaSign = Security.getProvider("SunRsaSign");
        System.out.println(provider);
        //插入提供者不影响property
        Security.insertProviderAt(sunRsaSign, 1);
        System.out.println(Security.getProperty("security.provider.1"));
        //直接修改property会修改内存中已加载的property信息，不会写入到文件
        Security.setProperty("security.provider.1", "sun.security.rsa.SunRsaSign");
        System.out.println(Security.getProperty("security.provider.1"));

    }
}
