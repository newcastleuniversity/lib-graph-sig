package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.List;

/** Commitment Group Element class */
public final class CommitmentGroupElement extends GroupElement {

  private final CommitmentGroup group;
  private final BigInteger value;

  public CommitmentGroupElement(final CommitmentGroup group, final BigInteger value) {
    this.group = group;
    this.value = value;
  }

  @Override
  public Group getGroup() {
    return this.group;
  }

  public BigInteger getOrder() {
    // TODO implement get Order
    throw new RuntimeException("not implemented");
  }

  @Override
  public BigInteger getValue() {
    return value;
  }

  @Override
  public QRElementPQ modPow(BigInteger x_z, BigInteger n)
  {
    /** TODO implement modpow  */
    throw new RuntimeException("not implemented");
  }

  @Override
  public QRElement multiply(QRElement val) {
    return null;
  }

  @Override
  public BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents) {
    // TODO implement multibase exponentiations
       throw new RuntimeException("not implemented");
  }

  @Override
  public QRElement multiply(BigInteger bigInteger) {
       throw new RuntimeException("not implemented");  }

  @Override
  public GroupElement modInverse(BigInteger bigInteger) {
    throw new RuntimeException("not implemented");
  }
}
