package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Group
 */
public interface Group {

    public BigInteger getOrder();
    //public int getModulusLength();
    public BigInteger getGenerator();
    public QRElement createGenerator();

    boolean isElement(BigInteger value);
}
