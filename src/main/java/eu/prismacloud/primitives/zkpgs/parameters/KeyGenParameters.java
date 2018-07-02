package eu.prismacloud.primitives.zkpgs.parameters;

import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.io.Serializable;

/** Class for key generation parameters displayed in table:params of the topocert documentation. */
public class KeyGenParameters implements Serializable {
  /** Bit length of the special RSA modulus */
  private int l_n = 2048;

  private static KeyGenParameters keyGenParameters;
  /** Bit length of the commitment group */
  private final int l_gamma;
  /** Bit length of the prime order of the subgroup of Γ */
  private final int l_rho;
  /** Maximal bit length of messages encoding vertices and 256 edges */
  private final int l_m;
  /** Number of reserved messages */
  private final int l_res;
  /** Bit length of the certificate component e */
  private final int l_e;
  /** Bit length of the interval the e values are taken from */
  private final int l_prime_e;
  /** Bit length of the certificate component v */
  private final int l_v;
  /** Security parameter for statistical zero-knowledge */
  private final int l_statzk;
  /** Bit length of the cryptographic hash function used for 256 the Fiat-Shamir Heuristic */
  private final int l_H;
  /** Security parameter for the security proof of the CL-scheme */
  private final int l_r;
  /**
   * The prime number generation to have an error probability to return a composite of \( 1 -
   * \frac{1}{2}^{l_{pt}} \)
   */
  private final int l_pt;

  /**
   * Instantiates a new Key gen parameters.
   *
   * @param l_n the bit length of the special RSA modulus
   * @param l_gamma the bit length of commitment group
   * @param l_rho the bit length of the prime order of the subgroup of Γ
   * @param l_m the maximal bit length of messages encoding vertices and 256 edges
   * @param l_res the number of reserved messages
   * @param l_e the bit length of the certificate component e
   * @param l_prime_e the bit length of the interval the e values are taken from
   * @param l_v the bit length for the certificate component v
   * @param l_statzk the security parameter for statistical zero-knowledge
   * @param l_H the bit length of SHA-256
   * @param l_r the security parameter for the security proof of the CL-scheme
   * @param l_pt the error probability of the prime number generation
   * @pre l_n != null && l_gamma != null && l_rho != null && l_m != null && l_res != null && l_e !=
   *     null && l_prime_e != null && l_v != null && l_statzk != null && l_H != null && l_r != null
   *     && l_pt != null
   * @post
   */
  private KeyGenParameters(
      int l_n,
      int l_gamma,
      int l_rho,
      int l_m,
      int l_res,
      int l_e,
      int l_prime_e,
      int l_v,
      int l_statzk,
      int l_H,
      int l_r,
      int l_pt) {

    Assert.notNull(l_n, "l_n parameter must not be null");
    Assert.notNull(l_gamma, "l_gamma parameter must not be null");
    Assert.notNull(l_rho, "l_rho parameter must not be null");
    Assert.notNull(l_m, "l_m parameter must not be null");
    Assert.notNull(l_res, "l_res parameter must not be null");
    Assert.notNull(l_e, "l_e parameter must not be null");
    Assert.notNull(l_prime_e, "l_prime_e parameter must not be null");
    Assert.notNull(l_v, "l_v parameter must not be null");
    Assert.notNull(l_statzk, "l_statzk parameter must not be null");
    Assert.notNull(l_H, "l_H parameter must not be null");
    Assert.notNull(l_r, "l_r parameter must not be null");
    Assert.notNull(l_pt, "l_pt parameter must not be null");

    this.l_n = l_n;
    this.l_gamma = l_gamma;
    this.l_rho = l_rho;
    this.l_m = l_m;
    this.l_res = l_res;
    this.l_e = l_e;
    this.l_prime_e = l_prime_e;
    this.l_v = l_v;
    this.l_statzk = l_statzk;
    this.l_H = l_H;
    this.l_r = l_r;
    this.l_pt = l_pt;
  }

  public static KeyGenParameters getKeyGenParameters() {
    return KeyGenParameters.keyGenParameters;
  }

  public static KeyGenParameters createKeyGenParameters(
      int l_n,
      int l_gamma,
      int l_rho,
      int l_m,
      int l_res,
      int l_e,
      int l_prime_e,
      int l_v,
      int l_statzk,
      int l_H,
      int l_r,
      int l_pt) {

    keyGenParameters =
        new KeyGenParameters(
            l_n, l_gamma, l_rho, l_m, l_res, l_e, l_prime_e, l_v, l_statzk, l_H, l_r, l_pt);

    return keyGenParameters;
  }

  public int getL_n() {
    return this.l_n;
  }

  public int getL_gamma() {
    return this.l_gamma;
  }

  public int getL_rho() {
    return this.l_rho;
  }

  public int getL_m() {
    return this.l_m;
  }

  public int getL_res() {
    return this.l_res;
  }

  public int getL_e() {
    return this.l_e;
  }

  public int getL_prime_e() {
    return this.l_prime_e;
  }

  public int getL_v() {
    return this.l_v;
  }

  public int getL_statzk() {
    return this.l_statzk;
  }

  public int getL_H() {
    return this.l_H;
  }

  public int getL_r() {
    return this.l_r;
  }

  public int getL_pt() {
    return this.l_pt;
  }
}
