package eu.prismacloud.primitives.grs.util.crypto;

import java.math.BigInteger;
import java.util.logging.Logger;

/** Chinese Remainder Theorem */
public class CRT {

  private static final Logger log = Logger.getLogger(CRT.class.getName());

  /**
   * Compute the Chinese Remainder Theorem based on <tt>alg:crt_men</tt> in topocert-doc
   *
   * <p>\( x \equiv x_p \bmod p \), \( x \equiv x_q \bmod q \)
   *
   * @param xp positive integer number \( xp \gt 0 \)
   * @param p prime factor of N
   * @param xq positive integer number \( xq \gt 0 \)
   * @param q prime factor of N
   * @return x solution for representation \( \bmod N \)
   */
  public static BigInteger computeCRT(
      final BigInteger xp, final BigInteger p, final BigInteger xq, final BigInteger q) {

    if (p.equals(q)) {
      throw new IllegalArgumentException("prime factors must be different");
    }

    if (p.gcd(q).compareTo(BigInteger.ONE) != 0) {
      throw new IllegalArgumentException("prime factors are not coprime");
    }

    BigInteger N = p.multiply(q);

    EEAlgorithm.computeEEAlgorithm(p, q);
    BigInteger X = EEAlgorithm.getS();
    //        log.info("X: " + X);
    BigInteger Y = EEAlgorithm.getT();
    //        log.info("Y: " + Y);

    //        log.info("res: " + X.multiply(p).add(Y.multiply(q)));
    BigInteger one_q = X.multiply(p).mod(N);
    //        log.info("1q: " + one_q);
    BigInteger one_p = Y.multiply(q).mod(N);
    //        log.info("1p: " + one_p);

    return xp.multiply(one_p).add(xq.multiply(one_q)).mod(N);
  }

  /**
   * Compute the CRT algorithm when 1p and 1q are pre-computed.
   *
   * @param xp the representation \( \bmod p \)
   * @param oneP the 1p element
   * @param xq the representation \( \bmod q \)
   * @param oneQ the 1q element
   * @param N the modulus N
   * @return the big integer
   */
  public static BigInteger computeCRT(
      final BigInteger xp,
      final BigInteger oneP,
      final BigInteger xq,
      final BigInteger oneQ,
      final BigInteger N) {

    return xp.multiply(oneP).add(xq.multiply(oneQ)).mod(N);
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
    BigInteger N = p.multiply(q);
    return Y.multiply(q).mod(N);
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
    BigInteger N = p.multiply(q);

    return X.multiply(p).mod(N);
  }

  /**
   * Convert an element x modulo N to its corresponding representation modulo p and modulo q.
   *
   * @param qr the qr
   * @param x element x in modulo N representation
   * @param p prime factor of N
   * @param q prime factor of N modulo p and modulo q representation \( (x \bmod p) , (x \bmod q) \)
   */
  public static void convertToPQ(
      final QRElementPQ qr, final BigInteger x, final BigInteger p, final BigInteger q) {
    // TODO check if this method should be in CRT class or in QRElementPQ
    qr.setPQRepresentation(x.mod(p), x.mod(q));
  }
}
