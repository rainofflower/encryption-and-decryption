package equal;

/**
 * @author YangHui
 */
public class ObjectB {

    public boolean equals(Object obj){
        return this.hashCode() == obj.hashCode();
    }

    public int hashCode(){
        return 1;
    }
}
