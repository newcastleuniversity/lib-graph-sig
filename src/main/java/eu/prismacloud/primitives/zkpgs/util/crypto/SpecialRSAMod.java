package eu.prismacloud.primitives.zkpgs.util.crypto;

import java.math.BigInteger;

/** Special RSA Modulus class */
public class SpecialRSAMod {

  private final BigInteger modN;
  private BigInteger p;
  private BigInteger q;
  private BigInteger pPrime;
  private BigInteger qPrime;
  private SafePrime sp;
  private SafePrime sq;

  /**
   * Instantiates a new Special rsa mod.
   *
   * @param modN the mod n
   * @param p the p
   * @param q the q
   * @param pPrime the p prime
   * @param qPrime the q prime
   */
  public SpecialRSAMod(
      BigInteger modN, BigInteger p, BigInteger q, BigInteger pPrime, BigInteger qPrime) {

    this.modN = modN;
    this.p = p;
    this.q = q;
    this.pPrime = pPrime;
    this.qPrime = qPrime;
  }

  /**
   * Instantiates a new Special rsa mod.
   *
   * @param modN the mod n
   * @param sp the sp
   * @param sq the sq
   */
  public SpecialRSAMod(BigInteger modN, SafePrime sp, SafePrime sq) {
    this.modN = modN;
    this.sp = sp;
    this.sq = sq;
  }

  /**
   * Gets modulus n.
   *
   * @return the n
   */
  public BigInteger getN() {
    return modN;
  }

  /**
   * Gets p.
   *
   * @return the p
   */
  public BigInteger getP() {
    return sp.getSafePrime();
  }

  /**
   * Gets q.
   *
   * @return the q
   */
  public BigInteger getQ() {
    return sq.getSafePrime();
  }

  /**
   * Gets prime.
   *
   * @return the prime
   */
  public BigInteger getpPrime() {
    return sp.getSophieGermain();
  }

  /**
   * Gets prime.
   *
   * @return the prime
   */
  public BigInteger getqPrime() {
    return sq.getSophieGermain();
  }
}
