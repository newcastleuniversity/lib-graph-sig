package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;

/** Group */
public abstract class Group {

  public abstract BigInteger getOrder();

  public abstract GroupElement getGenerator();

  public abstract BigInteger getModulus();

  public abstract boolean isElement(BigInteger value);

  public abstract GroupElement createGenerator();

  public abstract GroupElement createElement();

  public abstract GroupElement createElement(GroupElement s);
  
  public abstract GroupElement createElement(BigInteger value);
}
