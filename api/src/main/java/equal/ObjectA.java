package equal;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

/**
 * equals和hashCode
 *
 * @author YangHui
 */
public class ObjectA {

    public boolean equals(Object obj){
        return this.hashCode() == obj.hashCode();
    }

    public int hashCode(){
        return 1;
    }

    /**
     * HashMap 会使用hashCode和equals方法（当然如果两对象引用相同，是不会再调用equals方法的）比较key是否相同
     * 见源码 putVal方法
     * 如果hashCode（散列值）和equals都相同，则认为两对象是相同的
     */
    @Test
    public void testEquals(){
        ObjectA objectA1 = new ObjectA();
        ObjectB objectB1 = new ObjectB();
        ObjectA objectA2 = new ObjectA();
        ObjectB objectB2 = new ObjectB();
        System.out.println(objectA1.hashCode() == objectB1.hashCode());
        System.out.println(objectA1.equals(objectB1));
        System.out.println(objectA1.equals(objectA2));
        HashMap<Object, Object> map = new HashMap<>();
        map.put(objectA1, 1);
        map.put(objectB1, 1);
        map.put(objectA2, 1);
        map.put(objectB2, 1);
        System.out.println(map);
    }
}
