package eu.prismacloud.primitives.zkpgs.util;

import static java.nio.charset.StandardCharsets.UTF_8;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.JacobiSymbol;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** Crypto Utilities class for graph signature library */
public class GSUtils implements INumberUtils {

  private static final Logger log = Logger.getLogger(GSUtils.class.getName());

  private BigInteger modN;
  private SafePrime p;
  private SafePrime q;
  private BigInteger rho;
  private BigInteger gamma;
  private BigInteger g;
  private BigInteger r;
  private BigInteger h;
  private ArrayList<BigInteger> primeFactors;
  private static KeyGenParameters keyGenParameters;

  /** Instantiates a new Gs utils. */
  public GSUtils() {
    keyGenParameters = KeyGenParameters.getKeyGenParameters();
  }

  public BigInteger randomMinusPlusNumber(int bitlength) {
    SecureRandom secureRandom = new SecureRandom();

    /** TODO check if the computations for generating a +- random number are correct */

    /** TODO range is -2^bitlength+1 , + 2^bitlength -1 */
    BigInteger max = NumberConstants.TWO.getValue().pow(bitlength).subtract(BigInteger.ONE);
    BigInteger min = NumberConstants.TWO.getValue().pow(bitlength).add(BigInteger.ONE).negate();

    BigInteger maxWithoutSign = max.multiply(NumberConstants.TWO.getValue());

    BigInteger number = maxWithoutSign.add(BigInteger.ONE);

    while ((number.compareTo(max) > 0)
        || (number.subtract(max).compareTo(BigInteger.ZERO) == 0)
        || ((number.bitLength() + 1) != bitlength)) {

      number = new BigInteger(bitlength + 1, secureRandom);
    }
    
    BigInteger result = number.subtract(max);

//    log.info("result bitlength: " + result.bitLength());

    return result; //number.subtract(max);
  }

  public BigInteger multiBaseExp(
      List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN) {

    Assert.notNull(bases, "bases must not be null");
    Assert.notNull(exponents, "exponents must not be null");
    Assert.notNull(modN, "modulus N must not be null");
    Assert.checkSize(bases.size(), exponents.size(), "bases and exponents must have the same size");

    BigInteger result = BigInteger.ONE;
    for (int i = 0; i < bases.size(); i++) {
      result = result.multiply(bases.get(i).modPow(exponents.get(i), modN));
    }
    return result;
  }

  @Override
  public BigInteger multiBaseExpMap(
      Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
    GroupElement base;
    BigInteger exponent;

    Assert.notNull(bases, "bases must not be null");
    Assert.notNull(exponents, "exponents must not be null");
    Assert.notNull(modN, "modulus N must not be null");
    Assert.checkSize(bases.size(), exponents.size(), "bases and exponents must have the same size");

    List<GroupElement> basesList = new ArrayList<GroupElement>(bases.values());
    List<BigInteger> exponentList = new ArrayList<BigInteger>(exponents.values());

    BigInteger result = BigInteger.ONE;

    for (int i = 0; i < bases.size(); i++) {
      base = basesList.get(i);
      exponent = exponentList.get(i);
      if (exponent != null) {
        result = result.multiply(base.modPow(exponent, modN).getValue());
      }
    }
    return result;
  }

  @Override
  public BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength) {
    /** TODO check if the implementation is correct for [2^l_e, 2^l_e + 2^lPrime_e] */
    SecureRandom secureRandom = new SecureRandom();
    BigInteger min = NumberConstants.TWO.getValue().pow(minBitLength);
    BigInteger max = min.add(NumberConstants.TWO.getValue().pow(maxBitLength));
    BigInteger prime = max;

    while ((prime.compareTo(min) < 0) || (prime.compareTo(max) > 0) || !prime.isProbablePrime(80)) {
      BigInteger offset = new BigInteger(maxBitLength, secureRandom);
      prime = min.add(offset).nextProbablePrime();
    }

    return prime;
  }
  /**
   * Algorithm <tt>alg:generateSpecialRSAModulus</tt> - topocert-doc Generate Special RSA Modulus
   * modN Input: candidate integer a, prime factors of positive, odd integer modN: q_1, ..., q_r
   * Output: modN,p,q,p',q' \(modN = p * q \)
   */
  @Override
  public SpecialRSAMod generateSpecialRSAModulus() {

    p = this.generateRandomSafePrime(keyGenParameters);
    q = this.generateRandomSafePrime(keyGenParameters);
    modN = p.getSafePrime().multiply(q.getSafePrime());
    return new SpecialRSAMod(modN, p, q);
  }

  @Override
  public BigInteger createRandomNumber(BigInteger min, BigInteger max) {
    BigInteger randomNumber;
    BigInteger range;
    BigInteger temp;

    if (max.compareTo(min) < 0) {
      temp = min;
      min = max;
      max = temp;
    } else if (max.compareTo(min) == 0) {
      return min;
    }

    range = max.subtract(min).add(BigInteger.ONE);

    do {
      randomNumber = new BigInteger(range.bitLength(), new SecureRandom());
    } while (randomNumber.compareTo(range) >= 0);

    return randomNumber.add(min);
  }

  @Override
  public BigInteger createRandomNumber(final int bitLength) {
    return new BigInteger(bitLength, new SecureRandom());
  }

  @Override
  public CommitmentGroup generateCommitmentGroup() {

    // TODO check if the computations are correct
    rho = generateRandomPrime(keyGenParameters.getL_rho());
    gamma = computeCommitmentGroupModulus(rho);
    g = createCommitmentGroupGenerator(rho, gamma);
    r = createRandomNumber(BigInteger.ZERO, rho);
    h = g.modPow(r, gamma);

    return new CommitmentGroup(rho, gamma, g, h);
  }

  /**
   * Create generator for commitment group
   *
   * @param rho
   * @param gamma
   * @return
   */
  @Override
  public BigInteger createCommitmentGroupGenerator(final BigInteger rho, final BigInteger gamma) {
    BigInteger exp;
    BigInteger g;
    BigInteger h;

    exp = gamma.subtract(BigInteger.ONE).divide(rho);

    do {
      h = createRandomNumber(NumberConstants.TWO.getValue(), gamma);
      //      log.info("h: " + h);
      g = h.modPow(exp, gamma);
      //      log.info("g: " + g);

    } while (h.equals(BigInteger.ONE));

    return g;
  }

  /**
   * Algorithm <tt>alg:zps_gen</tt> - topocert-doc
   *
   * <p>Create generator for \( Z^*_\Gamma \).
   *
   * @param gamma the gamma modulus
   * @param primeFactors the prime factors
   * @return generator for \( Z^*_\Gamma \)
   */
  public BigInteger createZPSGenerator(
      final BigInteger gamma, final Iterable<BigInteger> primeFactors) {
    // TODO check if current algorithm is correct
    BigInteger alpha, beta, g = BigInteger.ONE;

    List<BigInteger> genFactors = new ArrayList<BigInteger>();

    for (BigInteger factor : primeFactors) {
      do {
        alpha = createRandomNumber(BigInteger.ONE, gamma.subtract(BigInteger.ONE));

        beta = alpha.modPow(factor, gamma);

      } while (beta.equals(BigInteger.ONE)); // || !beta.equals(BigInteger.valueOf(0)));
      genFactors.add(alpha.modPow(factor, gamma));
    }

    for (BigInteger genFactor : genFactors) {
      g = g.multiply(genFactor).mod(gamma);
    }

    return g;
  }

  /**
   * Compute group modulus for the commitment group.
   *
   * @param m prime number
   * @return gamma commitment group modulus
   */
  public BigInteger computeCommitmentGroupModulus(final BigInteger m) {

    ArrayList<BigInteger> primeFactors;
    BigInteger[] res;
    BigInteger gamma = BigInteger.ONE;

    do {

      primeFactors = generateRandomPrimeWithFactors(m);

      for (BigInteger factor : primeFactors) {
        gamma = gamma.multiply(factor);
      }

      this.rho = getMaxNumber(primeFactors);
      // rho divides gamma - 1
      res = gamma.divideAndRemainder(rho);
      //      log.info("remainder 1: " + res[1]);

    } while (!res[1].equals(
        BigInteger.ZERO)); // || gamma.bitLength() != KeyGenParameters.l_gamma.getValue());
    this.primeFactors = primeFactors;
    //    log.info("gamma: " + gamma);
    return gamma;
  }

  /**
   * Gets rho.
   *
   * @return the rho
   */
  public BigInteger getRho() {
    return this.rho;
  }

  /**
   * Gets prime factors.
   *
   * @return the prime factors
   */
  public ArrayList<BigInteger> getPrimeFactors() {
    return this.primeFactors;
  }

  /**
   * Algorithm <tt>alg:gen_numb_fact</tt> - topocert-doc Generate random number in factored form.
   *
   * @param m integer number \(m \geq 2 \)
   * @return prime number factorization \(p_1, \ldots, p_r \)
   */
  public ArrayList<BigInteger> generateRandomNumberWithFactors(final BigInteger m) {

    if (m.compareTo(NumberConstants.TWO.getValue()) < 0) {
      throw new IllegalArgumentException("integer number m must be >= 2");
    }

    BigInteger n = m;
    ArrayList<BigInteger> primeSeq = new ArrayList<BigInteger>();
    BigInteger y, x;

    do {

      primeSeq.clear();
      y = BigInteger.ONE;

      BigInteger min = BigInteger.valueOf(2);

      do {
        n = createRandomNumber(min, n);

        if (n.isProbablePrime(keyGenParameters.getL_pt())) {
          primeSeq.add(n);
          y = y.multiply(n);
        }

      } while (n.compareTo(min) > 0);

      x = createRandomNumber(BigInteger.ONE, m);

    } while (y.compareTo(m) <= 0 && x.compareTo(y) <= 0);

    return primeSeq;
  }

  /**
   * Algorithm <tt>alg:gen_prime_numb_fact</tt> - topocert-doc Generate random prime number along
   * with its factorization.
   *
   * @param m integer number \( m \geq 2 \)
   * @return prime number factorization \(p_1, \ldots, p_r \) of a prime number
   */
  public ArrayList<BigInteger> generateRandomPrimeWithFactors(final BigInteger m) {

    ArrayList<BigInteger> factors;
    BigInteger p;

    do {

      p = BigInteger.ONE;
      factors = generateRandomNumberWithFactors(m);

      for (BigInteger factor : factors) {
        p = p.multiply(factor);
      }
    } while (!GSUtils.isPrime(p.add(BigInteger.ONE)));
    // TODO check if correct bit length for gamma modulus
    return factors;
  }

  /**
   * Gets max number from a list of BigIntegers.
   *
   * @param numbers list of BigIntegers
   * @return the max BigInteger
   */
  public BigInteger getMaxNumber(final ArrayList<BigInteger> numbers) {

    return Collections.max(numbers);
  }

  /**
   * Algorithm <tt>alg:jacobi_shoup</tt> - topocert-doc Compute the Jacobi symbol (A | modN) Input:
   * candidate integer a, positive odd integer modN Output: Jacobi symbol (a | modN) Invariant: modN
   * is odd and positive Dependencies: splitPowerRemainder()
   *
   * @param alpha the alpha
   * @param modN the modN
   * @return the int
   */
  public static int computeJacobiSymbol(final BigInteger alpha, final BigInteger modN) {
    return JacobiSymbol.computeJacobiSymbol(alpha, modN);
  }

  /**
   * Algorithm <tt>alg:createElementOfZNS</tt> - topocert-doc Generate S' number
   *
   * <p>Dependencies: isElementOfZNS()
   *
   * @param modN the special RSA modulus
   * @return s_prime random number S' of QRN
   */
  public BigInteger createElementOfZNS(final BigInteger modN) {

    BigInteger s_prime;
    do {

      s_prime = createRandomNumber(NumberConstants.TWO.getValue(), modN.subtract(BigInteger.ONE));

    } while (!isElementOfZNS(s_prime, modN));

    return s_prime;
  }  // Post-condition: return BigInteger x in [2, N-1], gcd(x, N) = 1

  private boolean isElementOfZNS(final BigInteger s_prime, final BigInteger modN) {
    // check gcd(S', modN) = 1
    return (s_prime.gcd(modN).equals(BigInteger.ONE));
  }

  /**
   * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc Determines if an integer a is an element
   * of QRN
   *
   * @param alpha candidate integer a
   * @param modN positive odd integer (prime factors \( modN: q_1, \ldots , q_r \) )
   * @return true if a in QRN, false if a not in QRN Dependencies: jacobiSymbol()
   */
  @Override
  public Boolean elementOfQRN(final BigInteger alpha, final BigInteger modN) {
    return (alpha.compareTo(BigInteger.ZERO) > 0)
        && (alpha.compareTo(modN.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue()))
            <= 0)
        && (JacobiSymbol.computeJacobiSymbol(alpha, modN) == 1);
  } // TODO: This function does not seem to match what I was expecting.

  /**
   * Algorithm <tt>alg:verifySGeneratorOfQRN_alt</tt> - topocert-doc Evaluate generator S properties
   * Input: generator S, modulus modN Output: true or false
   *
   * @param s the s generator
   * @param modN
   * @return true if s is a generator of QRN or else return false
   */
  public Boolean verifySGeneratorOfQRN(final BigInteger s, BigInteger modN) {
    return s.subtract(BigInteger.ONE).gcd(modN).compareTo(BigInteger.ONE) == 0;
  }

  /**
   * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc Create generator of QRN Input: Special RSA
   * modulus modN, p', q' Output: generator S of QRN Dependencies: createElementOfZNS(),
   * verifySGenerator()
   */
  @Override
  public QRElement createQRNGenerator(final BigInteger modN) {

    BigInteger s;
    BigInteger s_prime;

    do {

      s_prime = createElementOfZNS(modN);
      s = s_prime.modPow(NumberConstants.TWO.getValue(), modN);

    } while (!verifySGeneratorOfQRN(s, modN));
    return new QRElement(s);
  }

  @Override
  public QRElement createQRNElement(final BigInteger modN) {

    BigInteger s;
    BigInteger s_prime;

    do {

      s_prime = createElementOfZNS(modN);
      s = s_prime.modPow(NumberConstants.TWO.getValue(), modN);

    } while (!elementOfQRN(s, modN));
    return new QRElement(s);
  }

  public BigInteger computeHash(final List<String> list, final int hashLength)
      throws NoSuchAlgorithmException {
    BigInteger hash;
    BigInteger checkedHash;
    MessageDigest messageDigest;
    messageDigest = MessageDigest.getInstance("SHA-" + hashLength);
    messageDigest.reset();
    for (String element : list) {
      messageDigest.update(element.getBytes(UTF_8));
    }
    hash = new BigInteger(1, messageDigest.digest());

    int diff = hashLength - hash.bitLength();
    if (diff > 0) {
      for (int i = 1; i <= diff; i++) {
        hash = hash.multiply(BigInteger.valueOf(2));
      }
    }
    checkedHash = hash;

    return checkedHash;
  }

  protected byte[] getBytes(BigInteger big) {
    byte[] bigBytes = big.toByteArray();
    if ((big.bitLength() % 8) != 0) {
      return bigBytes;
    } else {
      byte[] smallerBytes = new byte[big.bitLength() / 8];
      System.arraycopy(bigBytes, 1, smallerBytes, 0, smallerBytes.length);
      return smallerBytes;
    }
  }

  @Override
  public BigInteger computeA() {

    /** TODO finish implementation for computing A for the graph signature * */
    return BigInteger.valueOf(1);
  }

  /**
   * Algorithm <tt>alg:power_split</tt> - topocert-doc Compute the 2^ha' representation of integer a
   * Input: Odd integer a Output: Integers h and a' such that a = 2^ha' Post-conditions: a = 2^h a'
   * and a' is odd
   *
   * @return the array list
   */
  public static ArrayList<BigInteger> splitPowerRemainder() {
    return new ArrayList<BigInteger>(2);
  }

  /**
   * Algorithm <tt>alg:generateCLSignature</tt> - topocert-doc Generate Camenisch-Lysyanskaya
   * signature Input: message m Output: signature sigma
   *
   * @param m the m
   * @param base the base representation
   * @param signerPublicKey the signer's public key
   * @return the cl signature
   */
  public GSSignature generateSignature(
      final BigInteger m, final BaseRepresentation base, final SignerPublicKey signerPublicKey) {
    BigInteger A;
    BigInteger e;
    BigInteger v;
    BigInteger modN = signerPublicKey.getModN();
    GroupElement baseS = signerPublicKey.getBaseS();
    GroupElement baseZ = signerPublicKey.getBaseZ();
    GroupElement baseR;
    BigInteger Q;
    BigInteger d;

    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);
    v = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);

    baseR = base.getBase().modPow(m, modN);

    /** TODO check if the computations for generating the cl-signature are correct */
    BigInteger invertible = baseS.modPow(v, modN).multiply(baseR.getValue()).mod(modN);
    Q = baseZ.multiply(invertible.modInverse(modN)).mod(modN);
    A = Q.modPow(e.modInverse(modN), modN);

    return new GSSignature(A, e, v);
  }

  /**
   * Algorithm <tt>alg:generateSigProof</tt> - topocert-doc Generate Signature Proof of Knowledge
   * Input: R_0,S, Z, modN Output: signature proof of knowledge SPK
   *
   * @return the s po k
   */
  //  public static SPoK generateSignatureProofOfKnowledge() {
  //    return new SPoK();
  //  }

  /**
   * Algorithm <tt>alg:generateRandomSafePrime</tt> - topocert-doc Generate Random Safe Prime Input:
   * l_n bit-length, l_pt Output: safe prime p, Sophie Germain p'
   */
  @Override
  public SafePrime generateRandomSafePrime(KeyGenParameters keyGenParameters) {

    BigInteger a;
    BigInteger a_prime;

    do {
      a_prime = generateRandomPrime((keyGenParameters.getL_n() / 2) -1);
      a = NumberConstants.TWO.getValue().multiply(a_prime).add(BigInteger.ONE);
    } while (!isPrime(a));
    return new SafePrime(a, a_prime);
  }

  /**
   * Is prime boolean.
   *
   * @param number the number
   * @return the boolean
   */
  public static Boolean isPrime(final BigInteger number) {
    return number.isProbablePrime(keyGenParameters.getL_pt());
  }

  /**
   * Generate prime big integer with bitLength.
   *
   * @param bitLength length of prime number
   * @return the big integer
   */
  public BigInteger generateRandomPrime(final int bitLength) {
    return BigInteger.probablePrime(bitLength, new SecureRandom());
  }
}
