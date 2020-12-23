package sun;

import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import sun.security.util.SecurityConstants;

import java.net.SocketPermission;

/**
 * @author YangHui
 */
@Slf4j
public class SecurityManagerApi {

    @Test
    public void test01(){
        //vm启动参数加上-Djava.security.manager,让sun.misc.Launcher创建一个SecurityManager
        String property = System.getProperty("java.security.manager");
        System.out.println("---"+property);
        SecurityManager securityManager = System.getSecurityManager();
        //SecurityManager securityManager = new SecurityManager();
        //System.setSecurityManager(securityManager);
        //System.out.println(securityManager == System.getSecurityManager());
        Object securityContext = securityManager.getSecurityContext();
        /**
         * 下方checkPermission报错可以暂时在D:\Program Files\Java\jdk1.8.0_231\jre\lib\security中修改
         * java.policy文件
         * 添加权限
         * grant {
         *     permission java.security.AllPermission;
         * };
         */
        SocketPermission socketPermission = new SocketPermission("127.0.0.1" + ":" + 80,
                SecurityConstants.SOCKET_CONNECT_ACTION);
        securityManager.checkPermission(socketPermission);
        log.info("--context:{}--checkPermission:{}",securityContext.toString(),socketPermission.toString());
        Thread thread = new Thread(() -> {
            securityManager.checkPermission(socketPermission, securityContext);
            log.info("--context:{}--checkPermission:{}",securityContext.toString(),socketPermission.toString());
            Object currContext = securityManager.getSecurityContext();
            securityManager.checkPermission(socketPermission, currContext);
            log.info("--context:{}--checkPermission:{}",currContext.toString(),socketPermission.toString());
        });
        thread.start();
        try {
            thread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

    }
}
