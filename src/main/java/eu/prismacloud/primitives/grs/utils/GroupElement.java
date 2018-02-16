package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Group Element class
 */
public abstract class GroupElement {

    public abstract Group getGroup();
//    abstract BigInteger getOrder();
    public abstract BigInteger getValue();

    public abstract BigInteger modPow(BigInteger val, BigInteger n);

    public abstract BigInteger multiply(BigInteger val);
}
