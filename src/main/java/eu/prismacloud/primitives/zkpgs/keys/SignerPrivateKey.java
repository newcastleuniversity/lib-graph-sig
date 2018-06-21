package eu.prismacloud.primitives.zkpgs.keys;

import java.math.BigInteger;

public class SignerPrivateKey {
  private final BigInteger p;
  private BigInteger bigInteger;
  /** Safe prime <tt>q = 2*q' + 1</tt>. */
  private final BigInteger q;

  private BigInteger integer;
  private BigInteger x_r;
  private BigInteger x_r0;
  //    /**
  //     * Modulus <tt>n = p*q</tt>.
  //     */
  //    private  BigInteger n;
  /** Safe prime <tt>p'</tt>. */
  private BigInteger pPrime;
  /** Safe prime <tt>q'</tt>. */
  private BigInteger qPrime;

  private BigInteger x_r_0;
  private BigInteger x_Z;

  public SignerPrivateKey(
      final BigInteger p,
      final BigInteger p_prime,
      final BigInteger q,
      final BigInteger q_prime,
      final BigInteger x_R,
      final BigInteger x_R0,
      final BigInteger x_Z) {

    this.p = p;
    this.pPrime = p_prime;
    this.q = q;
    this.qPrime = q_prime;
    this.x_r = x_R;
    this.x_r0 = x_R0;
    this.x_Z = x_Z;
  }

  public SignerPrivateKey(
      final BigInteger p,
      final BigInteger p_prime,
      final BigInteger q,
      final BigInteger q_prime,
      final BigInteger x_r_0,
      final BigInteger x_Z) {

    this.p = p;
    this.pPrime = p_prime;
    this.q = q;
    this.qPrime = q_prime;
    this.x_r_0 = x_r_0;
    this.x_Z = x_Z;
  }

  public BigInteger getpPrime() {
    return pPrime;
  }

  public BigInteger getqPrime() {
    return qPrime;
  }

  public BigInteger getX_r() {
    return x_r;
  }

  public BigInteger getX_r0() {
    return x_r0;
  }

  public BigInteger getX_rZ() {
    return x_Z;
  }
}
