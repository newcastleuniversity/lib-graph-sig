package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Group Element class
 */
public abstract class GroupElement {

    public abstract Group getGroup();
//    abstract BigInteger getOrder();
    public abstract BigInteger getValue();
    
}
