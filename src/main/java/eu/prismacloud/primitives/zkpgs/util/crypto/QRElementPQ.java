package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.math.BigInteger;
import java.util.List;

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

  /**
   * Instantiates a new Qr element pq.
   *
   * @param value the value
   */
  public QRElementPQ(final BigInteger value) {
    super(value);
    this.value = value;
  }

  /**
   * Instantiates a new Qr element pq.
   *
   * @param qrGroupPQ the qr group pq
   * @param value the value
   */
  public QRElementPQ(final QRGroupPQ qrGroupPQ, final BigInteger value) {
    super(qrGroupPQ, value);

    this.qrGroupPQ = qrGroupPQ;
    this.value = value;
  }

  /**
   * Instantiates a new Qr element pq.
   *
   * @param qrGroupPQ the qr group pq
   * @param value the value
   * @param pPrime the p prime
   * @param qPrime the q prime
   */
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

  public QRElementPQ(QRElement crt) {
    super(crt.getValue());
  }

  /**
   * Gets xp.
   *
   * @return the xp
   */
  public BigInteger getXp() {
    return xp;
  }

  /**
   * Gets xq.
   *
   * @return the xq
   */
  public BigInteger getXq() {
    return xq;
  }

  /**
   * CRT representation
   *
   * @param xp the xp
   * @param xq the xq
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

  /**
   * Gets order.
   *
   * @return the order
   */
  public BigInteger getOrder() {
    return this.order;
  }

  @Override
  public QRElementPQ modPow(BigInteger exponent, BigInteger m) {
    //      compute exponentiation using CRT for modulo p and q representation
    BigInteger exp_p = exponent.mod(this.pPrime.subtract(BigInteger.ONE));
    BigInteger exp_q = exponent.mod(this.qPrime.subtract(BigInteger.ONE));
    BigInteger xp = modPow(exp_p, pPrime).getValue();

    BigInteger xq = modPow(exp_q, qPrime).getValue();
    // uses precomputation for 1p and 1q
    QRElement crt =
        CRT.computeCRT(
            xp,
            this.qrGroupPQ.getOneP(),
            xq,
            this.qrGroupPQ.getOneQ(),
            this.pPrime.multiply(this.qPrime));
    return new QRElementPQ(crt);
  }

  @Override
  public QRElement multiply(QRElement val) {
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

  /**
   * Multi base exp big integer.
   *
   * @param bases the bases
   * @param exponents the exponents
   * @return the big integer
   */
  public BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents) {
    Assert.notNull(bases, "bases must not be null");
    Assert.notNull(exponents, "exponents must not be null");
    Assert.checkSize(bases.size(), exponents.size(), "bases and exponents must have the same size");

    BigInteger modN = this.pPrime.multiply(this.qPrime);
    BigInteger result = BigInteger.ONE;
    for (int i = 0; i < bases.size(); i++) {
      result = result.multiply(bases.get(i).modPow(exponents.get(i), modN)).mod(modN);
    }
    return result;
  }
}
