package eu.prismacloud.primitives.zkpgs.util.crypto;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.math.BigInteger;
import java.util.logging.Logger;

/** Chinese Remainder Theorem */
public class CRT {

  private static final Logger log = Logger.getLogger(CRT.class.getName());


  private CRT(){}
  /**
   * Compute the Chinese Remainder Theorem based on <tt>alg:crt_men</tt> in topocert-doc
   *
   * <p>\( x \equiv x_p \bmod p \), \( x \equiv x_q \bmod q \)
   *
   * @param xp positive integer number \( xp \gt 0 \)
   * @param p prime factor of N
   * @param xq positive integer number \( xq \gt 0 \)
   * @param q prime factor of N
   * @pre xp != null && p != null && xq != null && q != null && p != q & p.gcd(q) != 1
   * @return x solution for representation \( \bmod modN \)
   */
  public static BigInteger computeCRT(
      final BigInteger xp, final BigInteger p, final BigInteger xq, final BigInteger q) {
	    Assert.notNull(xp, "xp must not be null");
	  Assert.notNull(p, "p must not be null");
    Assert.notNull(xq, "xq must not be null");
    Assert.notNull(q, "q must not be null");

    if (p.equals(q)) {
      throw new IllegalArgumentException("prime factors must be different");
    }

    if (p.gcd(q).compareTo(BigInteger.ONE) != 0) {
      throw new IllegalArgumentException("prime factors are not coprime");
    }

    BigInteger modN = p.multiply(q);

    EEAlgorithm.computeEEAlgorithm(p, q);
    BigInteger X = EEAlgorithm.getS();
    //        log.info("X: " + X);
    BigInteger Y = EEAlgorithm.getT();
    //        log.info("Y: " + Y);

    //        log.info("res: " + X.multiply(p).add(Y.multiply(q)));
    BigInteger one_q = X.multiply(p).mod(modN);
    //        log.info("1q: " + one_q);
    BigInteger one_p = Y.multiply(q).mod(modN);
    //        log.info("1p: " + one_p);

    return xp.multiply(one_p).add(xq.multiply(one_q)).mod(modN);
  }

  
  // TODO Provide more documentation for key functions such as CRT. What does it do? What are the arguments?
  /**
   * Compute the CRT algorithm when 1p and 1q are pre-computed.
   *
   * @param xp the representation \( \bmod p \)
   * @param oneP the 1p element
   * @param xq the representation \( \bmod q \)
   * @param oneQ the 1q element
   * @param modN the modulus N
   * @return the big integer
   */
  public static BigInteger computeCRT(
      final BigInteger xp,
      final BigInteger oneP,
      final BigInteger xq,
      final BigInteger oneQ,
      final BigInteger modN) {

    return xp.multiply(oneP).add(xq.multiply(oneQ)).mod(modN);
  }

  /**
   * Compute 1p for CRT algorithm.
   *
   * @param Y the y
   * @param q the q
   * @param p the p
   * @return the big integer
   */
  public static BigInteger compute1p(final BigInteger Y, final BigInteger p, final BigInteger q) {
    BigInteger modN = p.multiply(q);
    return Y.multiply(q).mod(modN);
  }

  /**
   * Compute 1q for CRT algorithm.
   *
   * @param X the x
   * @param p the p
   * @param q the q
   * @return the big integer
   */
  public static BigInteger compute1q(final BigInteger X, final BigInteger p, final BigInteger q) {
    BigInteger modN = p.multiply(q);
    return X.multiply(p).mod(modN);
  }

  // Method could mess up the group representation. Better have the representation mod p/mod q
  // generated whenever the QRElementPQ is created.
  
//  /**
//   * Convert an element x modulo modN to its corresponding representation modulo p and modulo q.
//   *
//   * @param qr the qr
//   * @param x element x in modulo modN representation
//   * @param p prime factor of N
//   * @param q prime factor of modN modulo p and modulo q representation \( (x \bmod p) , (x \bmod q)
//   *     \)
//   */
//  public static void convertToPQ(
//      final QRElementPQ qr, final BigInteger x, final BigInteger p, final BigInteger q) {
//    // TODO check if this method should be in CRT class or in QRElementPQ
//    qr.setPQRepresentation(x.mod(p), x.mod(q));
//  }
}
