package util;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * @author YangHui
 * @date 2021-02-14 11:58
 */
public class KeyUtils {

    public static String getKeyHexString(byte[] key){
        return Hex.encodeHexString(key);
    }

    public static byte[] getKey(String key) throws DecoderException {
        return Hex.decodeHex(key);
    }
}
