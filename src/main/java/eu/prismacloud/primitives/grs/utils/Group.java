package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Group
 */
public abstract class Group {

    public abstract BigInteger getOrder();
    //public int getModulusLength();
    public abstract GroupElement getGenerator();
    public abstract BigInteger getModulus();
//    public abstract GroupElement createGenerator(BigInteger rho, BigInteger gamma);
    public abstract boolean  isElement(BigInteger value);

    public abstract GroupElement createGenerator();

    public abstract GroupElement createElement();

    public abstract GroupElement createElement(GroupElement s);
}
