package sun;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;
import java.util.Map;

/**
 * @author YangHui
 */
@Slf4j
public class SecurityApi {

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
        System.out.printf(property);
    }
}
