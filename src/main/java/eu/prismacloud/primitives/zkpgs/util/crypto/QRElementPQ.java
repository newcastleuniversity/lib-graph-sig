package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

/**
 * Class that represents an element in the Quadratic Residues group when the modulus factorization
 * is known.
 */
public class QRElementPQ extends QRElement {

  private static final long serialVersionUID = 6659291010231881173L;
  private final QRGroupPQ qrGroupPQ;
  private final BigInteger value;
  private BigInteger order;
  private final BigInteger xp;
  private final BigInteger xq;
  private BigInteger lgdrP;
  private BigInteger lgdrQ;

  private static final Logger log = Logger.getLogger(QRElementPQ.class.getName());

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
    BigInteger expP = this.xp.modPow(exponent, this.qrGroupPQ.getP());

    BigInteger expQ =  this.xq.modPow(exponent, this.qrGroupPQ.getQ());
    
    // uses precomputation for 1p and 1q
    BigInteger crt =
        CRT.computeCRT(
            expP,
            this.qrGroupPQ.getOneP(),
            expQ,
            this.qrGroupPQ.getOneQ(),
            this.qrGroupPQ.getModulus());
    
    return new QRElementPQ(this.qrGroupPQ, crt);
  }

  @Override
  public QRElementPQ modInverse(){
     return new QRElementPQ(this.qrGroupPQ, this.value.modInverse(this.getGroup().getModulus()));
  }

  @Override
  public QRElementPQ multiply(GroupElement multiplier) {
    BigInteger multiplierP = (multiplier.getValue()).mod(this.qrGroupPQ.getP());
    BigInteger multiplierQ = (multiplier.getValue()).mod(this.qrGroupPQ.getQ());
    
    // uses precomputation for 1p and 1q
    BigInteger productP = (this.xp.multiply(multiplierP)).mod(this.qrGroupPQ.getP());
    BigInteger productQ = (this.xq.multiply(multiplierQ)).mod(this.qrGroupPQ.getQ());
    
	BigInteger crt = CRT.computeCRT(
    	productP,
        this.qrGroupPQ.getOneP(),
        productQ,
        this.qrGroupPQ.getOneQ(),
        this.qrGroupPQ.getModulus());
	
//	log.info("----- Multiplication Profile -----");
//	log.info("element value = " + this.value);
//	log.info("element in ZPS = " + this.xp);
//	log.info("element in ZQS = " + this.xq);
//	log.info("---");
//	log.info("multiplier = " + multiplier);
//	log.info("multiplier in ZPS = " + multiplierP);
//	log.info("multiplier in ZQS = " + multiplierQ);
//	log.info("---");
//	log.info("product in ZPS = " + productP);
//	log.info("product in ZQS = " + productQ);
//	log.info("product in ZNS = " + crt);
	
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

    QRElementPQ result = (QRElementPQ) this.qrGroupPQ.getOne();
    for (int i = 0; i < bases.size(); i++) {
      result = result.multiply(bases.get(i).modPow(exponents.get(i)));
    }
    return result;
  }
}
