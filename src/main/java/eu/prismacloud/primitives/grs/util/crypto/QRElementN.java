package eu.prismacloud.primitives.grs.util.crypto;

import java.math.BigInteger;

/**
 * Class that represents an element in Quadratic Residues group without knowing the factorization of
 * modulus N.
 */
public class QRElementN extends QRElement {
  private QRGroupN qrGroup;
  private BigInteger number;

  public QRElementN(final QRGroupN qrGroup, final BigInteger number) {

    super(qrGroup, number);
    this.qrGroup = qrGroup;
    this.number = number;
  }

  public QRElementN(final BigInteger value) {
    super(value);
  }

  public QRElementN(final Group group, final BigInteger value) {
    super(group, value);
  }

  @Override
  public Group getGroup() {
    return qrGroup;
  }

  @Override
  public BigInteger getValue() {
    return number;
  }

  @Override
  public BigInteger multiply(BigInteger val) {
    return super.multiply(val);
  }
}
