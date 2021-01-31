package sun;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * @author YangHui
 */
public class CipherApi {

    @Test
    public void test1() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("DES");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        //初始化Cipher对象，用于包装
        cipher.init(Cipher.WRAP_MODE, secretKey);
        //包装秘密密钥
        byte[] k = cipher.wrap(secretKey);

        //解包初始化
        cipher.init(Cipher.UNWRAP_MODE, secretKey);
        //解包
        Key key = cipher.unwrap(k, "DES", Cipher.SECRET_KEY);

        String data = "original data";
        //初始化Cipher对象，用于加密操作
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //加密
        byte[] input = cipher.doFinal(data.getBytes());
        //解密初始化
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        //解密
        byte[] decryptData = cipher.doFinal(input);
        String decryptStr = new String(decryptData);
        System.out.println(decryptStr);
        Assert.assertEquals(data, decryptStr);
    }

    /**
     * CipherInputStream 密钥输入流
     * CipherOutputStream 密钥输出流
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IOException
     */
    @Test
    public void test2() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
        String plainText = "啦啦啦啦啦啦,流水的账号，铁打的密码";
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("DES");
        File file = new File("F:\\server\\resource\\cipher-data.txt");
        //加密初始化
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //实例化 密钥输出流
        CipherOutputStream cipherOutputStream = new CipherOutputStream(new FileOutputStream(file), cipher);
        //使用DataOutputStream对象 包装CipherOutputStream对象
        DataOutputStream dataOutputStream = new DataOutputStream(cipherOutputStream);
        //向输出流写入待加密数据
        dataOutputStream.writeUTF(plainText);
        dataOutputStream.flush();
        dataOutputStream.close();
        /**
         * 解密的密钥需要与加密密钥对应，否则会解密失败
         * 如本例中KeyGenerator.getInstance("DES")生成的对称密钥，如果加密使用的secretKey与解密的secretKey不是同一个，会报错：
         * javax.crypto.BadPaddingException: Given final block not properly padded
         */
        //解密初始化
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        CipherInputStream cipherInputStream = new CipherInputStream(new FileInputStream(file), cipher);
        DataInputStream dataInputStream = new DataInputStream(cipherInputStream);
        //读出解密后的数据
        String output = dataInputStream.readUTF();
        System.out.println(output);
        dataInputStream.close();
    }

    /**
     * SealedObject类
     */
    @Test
    public void test3() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException {
        String input = "SealedObject";
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance(keyGenerator.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        SealedObject sealedObject = new SealedObject(input, cipher);
        Cipher cipher1 = Cipher.getInstance(keyGenerator.getAlgorithm());
        cipher1.init(Cipher.DECRYPT_MODE, secretKey);
        String output = (String)sealedObject.getObject(cipher1);
        System.out.println(output);
    }
}
