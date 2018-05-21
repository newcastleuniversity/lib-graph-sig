package eu.prismacloud.primitives.grs.keys;

import java.math.BigInteger;

public class SignerPrivateKey {
  private BigInteger p;
  /** Safe prime <tt>q = 2*q' + 1</tt>. */
  private BigInteger q;
  //    /**
  //     * Modulus <tt>n = p*q</tt>.
  //     */
  //    private  BigInteger n;
  /** Safe prime <tt>p'</tt>. */
  private BigInteger pPrime;
  /** Safe prime <tt>q'</tt>. */
  private BigInteger qPrime;

  private BigInteger x_r_0;
  private BigInteger x_z;

  public SignerPrivateKey() {
    // TODO Auto-generated constructor stub
  }

  public SignerPrivateKey(
      final BigInteger p,
      final BigInteger p_prime,
      final BigInteger q,
      final BigInteger q_prime,
      final BigInteger x_r_0,
      final BigInteger x_z) {

    this.p = p;
    this.pPrime = p_prime;
    this.q = q;
    this.qPrime = q_prime;
    this.x_r_0 = x_r_0;
    this.x_z = x_z;
  }

  /* TODO return public key corresponding to this private key */
  public final SignerPrivateKey getPublicKey() {
    return this;
  }
}
