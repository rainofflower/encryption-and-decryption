package sun;

import org.junit.Test;

import java.util.zip.CRC32;

/**
 * CRC 循环冗余校验
 * @author YangHui
 */
public class CRCApi {

    @Test
    public void test(){
        String str = "测试CRC-32";
        CRC32 crc32 = new CRC32();
        crc32.update(str.getBytes());
        String hexString = Long.toHexString(crc32.getValue());
        System.out.println("原文："+str);
        System.out.println("CRC-32:"+hexString);
    }
}
