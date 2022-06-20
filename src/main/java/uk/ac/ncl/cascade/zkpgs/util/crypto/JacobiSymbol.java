package uk.ac.ncl.cascade.zkpgs.util.crypto;

import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.logging.Logger;

/** Jacobi Symbol */
public class JacobiSymbol {
  private static final Logger log = Logger.getLogger(JacobiSymbol.class.getName());
  //    private static int sigma;
  private static BigInteger h;
  private static BigInteger alpha_prime;

  private JacobiSymbol() {}

  /**
   * Compute the jacobiSymbol based on <tt>alg:jacobi_shoup</tt> in topocert-doc
   *
   * @param alpha candidate integer
   * @param modN positive odd integer
   * @pre \( alpha != null \and modN != null \)
   * @return jacobi symbol (a|N)
   */
  public static int computeJacobiSymbol(BigInteger alpha, BigInteger modN) {
    Assert.notNull(alpha, "A value for alpha is needed");
    Assert.notNull(modN, "A value for modN is needed");

    if (modN.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO)) {
      throw new IllegalArgumentException("Use an odd integer.");
    }

    int sigma = 1;

    do {
      alpha = alpha.mod(modN);

      if (alpha.equals(BigInteger.ZERO)) {

        if (modN.equals(BigInteger.ONE)) return sigma;
        else return 0;
      }

      h = BigInteger.valueOf(alpha.getLowestSetBit());
      alpha_prime = alpha.shiftRight(h.intValue());

      if (!isCongruent(h, BigInteger.ZERO, NumberConstants.TWO.getValue())
          && !isCongruent(modN, BigInteger.ONE, NumberConstants.EIGHT.getValue())
          && !isCongruent(modN, NumberConstants.SEVEN.getValue(), NumberConstants.EIGHT.getValue()))
        sigma = -sigma;

      if (!isCongruent(alpha_prime, BigInteger.ONE, NumberConstants.FOUR.getValue())
          && !isCongruent(modN, BigInteger.ONE, NumberConstants.FOUR.getValue())) sigma = -sigma;

      alpha = modN;
      modN = alpha_prime;

    } while (true);
  }

  /**
   * Computes the greatest power of base 2 contained in an odd integer a and its remainder a' based
   * on <tt>alg:power_split</tt> in topocert-doc
   *
   * @param alpha odd integer
   * @return alpha_prime remainder
   */
  public static BigInteger splitPowerRemainder(BigInteger alpha) {

    h = BigInteger.valueOf(alpha.bitLength()).subtract(BigInteger.ONE);
    BigInteger b = BigInteger.ONE.shiftLeft(h.intValue());
    BigInteger k = alpha.subtract(b);
    return k;
  }

  /**
   * Check if two BigIntegers are congruent with respect to a supplied modulus.
   *
   * @param a integer for calculating congruency
   * @param b integer for calculating congruency
   * @param mod modulus
   * @return true if a and b are congruent, false otherwise
   */
  public static boolean isCongruent(BigInteger a, BigInteger b, BigInteger mod) {
    return a.mod(mod).compareTo(b) == 0;  // TODO This congruence function is not quite what we'd want: Rather compute modN divides a-b.
    // I'd suggest: mod.remainder(a.subtract(b)).equals(BigInteger.ZERO)
  }

  private static int j; // TODO not thread-safe. Make local temporary variable.

  /**
   * Compute Jacobi symbol based on Algorithm 1.4 in "Cryptography made simple" book
   *
   * @param a candidate integer
   * @param b positive odd integer
   * @return jacobi symbol (a|b)
   */
  public static int computeJacobiSymbolBA(BigInteger a, BigInteger b) {
    // b<= 0 or b (mod 2) = 0

    boolean k = b.compareTo(BigInteger.ZERO) <= 0;
    boolean o = b.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO);
    BigInteger temp;

    if (b.compareTo(BigInteger.ZERO) <= 0
        || b.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO)) return 0;

    j = 1;

    if (a.compareTo(BigInteger.ZERO) < 0) {
      a = a.negate();

      // b (mod 4) = 3
      if (b.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue())) {
        j = -j;
      }
    }

    while (a.compareTo(BigInteger.ZERO) != 0) {

      // a (mod 2) = 0
      while (a.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO)) {

        // a = a/2
        a = a.divide(NumberConstants.TWO.getValue());

        // b (mod 8) = 3 or b (mod 8) = 5
        if (b.mod(NumberConstants.EIGHT.getValue()).equals(NumberConstants.THREE.getValue())
            || b.mod(NumberConstants.EIGHT.getValue()).equals(NumberConstants.FIVE.getValue())) {
          j = -j;
        }
      }

      temp = a;
      a = b;
      b = temp;

      // a (mod 4) = 3 and b (mod 4) = 3
      if (a.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue())
          && b.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue())) {
        j = -j;
      }

      a = a.mod(b);
    }
    if (b.equals(BigInteger.ONE)) return j;
    else return 0;
  }
}
