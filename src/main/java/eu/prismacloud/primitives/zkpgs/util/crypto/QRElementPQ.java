package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;

/**
 * Class that represents an element in the Quadratic Residues group when the modulus factorization
 * is known.
 */
public class QRElementPQ extends QRElement {
  private BigInteger pPrime;
  private BigInteger qPrime;
  private QRGroupPQ qrGroupPQ;
  private BigInteger value;
  private BigInteger order;
  private BigInteger xp;
  private BigInteger xq;

  public QRElementPQ(final BigInteger value) {
    super(value);
    this.value = value;
  }

  public QRElementPQ(final QRGroupPQ qrGroupPQ, final BigInteger value) {
    super(qrGroupPQ, value);

    this.qrGroupPQ = qrGroupPQ;
    this.value = value;
  }

  public QRElementPQ(
      final QRGroupPQ qrGroupPQ,
      final BigInteger value,
      final BigInteger pPrime,
      final BigInteger qPrime) {
    super(qrGroupPQ, value);
    this.qrGroupPQ = qrGroupPQ;
    this.value = value;
    this.order = pPrime.multiply(qPrime);
    this.pPrime = pPrime;
    this.qPrime = qPrime;
  }

  public BigInteger getXp() {
    return xp;
  }

  public BigInteger getXq() {
    return xq;
  }

  /**
   * CRT representation
   *
   * @param xp
   * @param xq
   */
  public void setPQRepresentation(BigInteger xp, BigInteger xq) {
    this.xp = xp;
    this.xq = xq;
  }

  @Override
  public Group getGroup() {
    return this.qrGroupPQ;
  }

  @Override
  public BigInteger getValue() {
    return this.value;
  }

  public BigInteger getOrder() {
    return this.order;
  }

  @Override
  public BigInteger modPow(BigInteger exponent, BigInteger m) {
    //      compute exponentiation using CRT for modulo p and q representation
    BigInteger exp_p = exponent.mod(this.pPrime.subtract(BigInteger.ONE));
    BigInteger exp_q = exponent.mod(this.qPrime.subtract(BigInteger.ONE));
    BigInteger xp = super.modPow(exp_p, pPrime);

    BigInteger xq = super.modPow(exp_q, qPrime);

    // uses precomputation for 1p and 1q
    return CRT.computeCRT(
        xp,
        this.qrGroupPQ.getOneP(),
        xq,
        this.qrGroupPQ.getOneQ(),
        this.pPrime.multiply(this.qPrime));
  }

  @Override
  public BigInteger multiply(BigInteger val) {
    BigInteger xp1 = this.value.mod(this.pPrime);
    BigInteger xq1 = this.value.mod(this.qPrime);

    BigInteger xp2 = val.mod(this.pPrime);
    BigInteger xq2 = val.mod(this.qPrime);

    // uses precomputation for 1p and 1q
    return CRT.computeCRT(
        xp1.multiply(xp2),
        this.qrGroupPQ.getOneP(),
        xq1.multiply(xq2),
        this.qrGroupPQ.getOneQ(),
        this.pPrime.multiply(this.qPrime));
  }
}
