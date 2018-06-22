package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

/** Group Element class */
public abstract class GroupElement {

  public abstract Group getGroup();
  //    abstract BigInteger getOrder();
  public abstract BigInteger getValue();

  public abstract GroupElement modPow(BigInteger exponent, BigInteger modulus);

  public abstract BigInteger multiply(BigInteger value);

  public abstract BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents);
}
