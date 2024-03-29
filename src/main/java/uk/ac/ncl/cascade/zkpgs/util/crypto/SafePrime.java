package uk.ac.ncl.cascade.zkpgs.util.crypto;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.logging.Logger;

/** Wrapper for generating safe primes */
public class SafePrime implements Serializable {

  private static final long serialVersionUID = 3099828170257665401L;
  private BigInteger a;
  private SafePrime safePrime;
  private BigInteger aPrime;

  private static final Logger log = Logger.getLogger(SafePrime.class.getName());

  /**
   * Instantiates a new Safe prime p with its corresponding Sophie Germain prime p'. \( p = 2p' + 1
   * \)
   *
   * @param safePrime the safe prime
   * @param sophieGermain the Sophie Germain prime
   */
  public SafePrime(final BigInteger safePrime, final BigInteger sophieGermain) {
    this.a = safePrime;
    this.aPrime = sophieGermain;
  }

  public SafePrime() {}

  public BigInteger getSafePrime() {
    return a;
  }

  public BigInteger getSophieGermain() {
    return aPrime;
  }

  /**
   * Generates random safe prime safe prime.
   *
   * @param keyGenParameters the key gen parameters
   * @return the safe prime
   */
  public SafePrime generateRandomSafePrime(KeyGenParameters keyGenParameters) {
    CryptoUtilsFacade cuf = new CryptoUtilsFacade();
    safePrime = cuf.computeRandomSafePrime(keyGenParameters);
    return new SafePrime(safePrime.a, safePrime.aPrime);
  }
}
