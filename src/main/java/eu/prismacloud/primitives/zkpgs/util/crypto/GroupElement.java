package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

/** Group Element class */
public abstract class GroupElement {

  public abstract Group getGroup();
  //    abstract BigInteger getOrder();
  public abstract BigInteger getValue();

  public abstract QRElement modPow(BigInteger exponent, BigInteger modulus);

  public abstract QRElement multiply(QRElement value);

  public abstract BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents);

  public abstract QRElement multiply(BigInteger bigInteger);

  public abstract GroupElement modInverse(BigInteger bigInteger);
}
