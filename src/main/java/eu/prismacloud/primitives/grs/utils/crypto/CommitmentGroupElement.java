package eu.prismacloud.primitives.grs.utils.crypto;

import java.math.BigInteger;

/** Commitment Group Element class */
public final class CommitmentGroupElement extends GroupElement {

  private final CommitmentGroup group;
  private final BigInteger value;

  public CommitmentGroupElement(final CommitmentGroup group, final BigInteger value) {
    this.group = group;
    this.value = value;
  }

  public Group getGroup() {
    return this.group;
  }

  public BigInteger getOrder() {
    // TODO implement get Order
    throw new RuntimeException("not implemented");
  }

  public BigInteger getValue() {
    return value;
  }

  @Override
  public BigInteger modPow(BigInteger x_z, BigInteger n) {
    return null;
  }

  @Override
  public BigInteger multiply(BigInteger val) {
    return null;
  }
}
