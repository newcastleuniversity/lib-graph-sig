package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/** Abstract class for groups */
public abstract class AbstractGroup {
  protected abstract BigInteger computeGroupOrder(BigInteger pPrime, BigInteger qPrime);

  public abstract BigInteger getOrder();

  public abstract BigInteger getModulus();

  public abstract QRElement createGenerator();
}
