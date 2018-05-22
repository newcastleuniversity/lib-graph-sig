package eu.prismacloud.primitives.grs.util.crypto;

import java.math.BigInteger;

/**
 * Class that represents an element in the Quadratic Residues group that the modulus factorization
 * is known and the discrete logarithms of the exponents.
 */
public class QRElementPQDlog extends QRElement {
  private QRGroupPQ qrGroupPQ;
  private BigInteger number;

  public QRElementPQDlog(final BigInteger value) {
    super(value);
  }

  public QRElementPQDlog(final QRGroupPQ qrGroupPQ, final BigInteger number) {
    super(qrGroupPQ, number);

    this.qrGroupPQ = qrGroupPQ;
    this.number = number;
  }

  @Override
  public Group getGroup() {
    return this.qrGroupPQ;
  }

  @Override
  public BigInteger getValue() {
    return this.number;
  }
}
