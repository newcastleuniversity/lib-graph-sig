package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;
import java.util.logging.Logger;

/** Extended Euclidean Algorithm */
public class EEAlgorithm {

  private static final Logger log = Logger.getLogger(EEAlgorithm.class.getName());

  private static BigInteger r;
  private static BigInteger r_prime;
  private static BigInteger s;
  private static BigInteger s_prime;
  private static BigInteger t;
  private static BigInteger t_prime;
  private static BigInteger r_prime_prime;
  private static BigInteger q;
  private static BigInteger d;

  private EEAlgorithm() {}

  /**
   * Compute the Extended Euclidean Algorithm based on <tt>alg:eea_schoup</tt> in topocert-doc
   *
   * @param a positive BigInteger \( \geq 0 \)
   * @param b positive BigInteger \( \geq 0 \)
   * @return d, s, t
   */
  public static void computeEEAlgorithm(final BigInteger a, final BigInteger b) {

    if (a.compareTo(BigInteger.ZERO) <= 0)
      throw new IllegalArgumentException("EEA requires positive integers");

    if (b.compareTo(BigInteger.ZERO) <= 0)
      throw new IllegalArgumentException("EEA requires positive integers");

    BigInteger temps;
    BigInteger tempt;

    r = a;
    r_prime = b;
    s = BigInteger.ONE;
    temps = BigInteger.ZERO;
    tempt = BigInteger.ONE;
    s_prime = BigInteger.ZERO;
    t = BigInteger.ZERO;
    t_prime = BigInteger.ONE;

    while (r_prime.compareTo(BigInteger.ZERO) != 0) {

      q = r.divide(r_prime);
      r_prime_prime = r.mod(r_prime);

      r = r_prime;

      r_prime = r_prime_prime;

      temps = s_prime;
      tempt = t_prime;

      t_prime = t.subtract(t_prime.multiply(q));
      s_prime = s.subtract(s_prime.multiply(q));

      s = temps;
      t = tempt;
    }

    d = r;

  }

  public static BigInteger getS() {
    return s;
  }

  public static BigInteger getT() {
    return t;
  }

  public static BigInteger getD() {
    return d;
  }
}
