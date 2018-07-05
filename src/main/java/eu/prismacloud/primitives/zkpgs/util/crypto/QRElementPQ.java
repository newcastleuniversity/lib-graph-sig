package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.math.BigInteger;
import java.util.List;

/**
 * Class that represents an element in the Quadratic Residues group when the modulus factorization
 * is known.
 */
public class QRElementPQ extends QRElement {
  private final QRGroupPQ qrGroupPQ;
  private final BigInteger value;
  private BigInteger order;
  private final BigInteger xp;
  private final BigInteger xq;



  /**
   * Instantiates a new QR element with known p and q.
   *
   * @param qrGroupPQ the Quadratic Residues with known modulus factorization.
   * @param value the value
   */
  public QRElementPQ(final QRGroupPQ qrGroupPQ, final BigInteger value) {
    super(qrGroupPQ, value);
    /** TODO add check for the QR Elements */
    
    this.qrGroupPQ = qrGroupPQ;
    this.value = value;
    this.xp = this.value.mod(qrGroupPQ.getP());
    this.xq = this.value.mod(qrGroupPQ.getQ());
    
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
  @Override
  public BigInteger getElementOrder() {
	  // TODO compute the order if it has not been computed before.
    return this.order;
  }

  @Override
  public QRElement modPow(BigInteger exponent) {
	  // TODO The computation does not work.
	  // The order of the QR_p is p', the order of QR_q is q', not those values minus 1.
    //      compute exponentiation using CRT for modulo p and q representation
    BigInteger xp = this.getValue().modPow(exponent, this.qrGroupPQ.getP());

    BigInteger xq =  this.getValue().modPow(exponent, this.qrGroupPQ.getOneQ());
    // uses precomputation for 1p and 1q
    BigInteger crt =
        CRT.computeCRT(
            xp,
            this.qrGroupPQ.getOneP(),
            xq,
            this.qrGroupPQ.getOneQ(),
            this.qrGroupPQ.getModulus());
    return new QRElementPQ(this.qrGroupPQ, crt);
  }

  @Override
  public QRElementPQ modInverse(){
     return new QRElementPQ(this.qrGroupPQ, this.value.modInverse(this.getGroup().getModulus()));
  }

  @Override
  public QRElementPQ multiply(GroupElement val) {
    BigInteger xp1 = this.value.mod(this.qrGroupPQ.getP());
    BigInteger xq1 = this.value.mod(this.qrGroupPQ.getQ());

    BigInteger xp2 = val.getValue().mod(this.qrGroupPQ.getP());
    BigInteger xq2 = val.getValue().mod(this.qrGroupPQ.getQ());

    // uses precomputation for 1p and 1q
    BigInteger crt = CRT.computeCRT(
        xp1.multiply(xp2),
        this.qrGroupPQ.getOneP(),
        xq1.multiply(xq2),
        this.qrGroupPQ.getOneQ(),
        this.qrGroupPQ.getModulus());
    return new QRElementPQ(this.qrGroupPQ, crt);
  }

  /**
   * Multi base exp big integer.
   *
   * @param bases the bases
   * @param exponents the exponents
   * @return the big integer
   */
  public QRElementPQ multiBaseExp(List<GroupElement> bases, List<BigInteger> exponents) {
    Assert.notNull(bases, "bases must not be null");
    Assert.notNull(exponents, "exponents must not be null");
    Assert.checkSize(bases.size(), exponents.size(), "bases and exponents must have the same size");

    QRElementPQ result = this.qrGroupPQ.getOne();
    for (int i = 0; i < bases.size(); i++) {
      result = result.multiply(bases.get(i).modPow(exponents.get(i)));
    }
    return result;
  }
}
