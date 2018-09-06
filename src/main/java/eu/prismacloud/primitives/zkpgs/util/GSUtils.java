package eu.prismacloud.primitives.zkpgs.util;

import static java.nio.charset.StandardCharsets.UTF_8;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.Group;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.JacobiSymbol;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** Crypto Utilities class for graph signature library */
public class GSUtils implements INumberUtils {

	private Logger log = GSLoggerConfiguration.getGSlog();
	private final SecureRandom secureRandom;

	private BigInteger modN;
	private SafePrime p;
	private SafePrime q;
	private BigInteger rho;
	private BigInteger gamma;
	private BigInteger g;
	private BigInteger r;
	private BigInteger h;
	private ArrayList<BigInteger> primeFactors;

	private HashMap<Integer, BigInteger> boundMap = new HashMap<Integer, BigInteger>();

	/** Instantiates a new Gs utils. */
	public GSUtils() {
		this.secureRandom = new SecureRandom();
	}

	/**
	 * Computes a random number in the range of [-2^bitlength+1, +2^bitlength-1]
	 *
	 * @param bitlength the bitlength for the random number
	 * @return random number in the range of [-2^bitlength+1, +2^bitlength-1]
	 */
	@Override
	public BigInteger randomMinusPlusNumber(int bitlength) {
		/** TODO check if the computations for generating a +- random number are correct */
		/** TODO range is -2^bitlength+1 , + 2^bitlength -1 */
		BigInteger max = NumberConstants.TWO.getValue().pow(bitlength).subtract(BigInteger.ONE);
		BigInteger positiveMin = NumberConstants.TWO.getValue().pow(bitlength);
		BigInteger negativeMin = positiveMin.add(BigInteger.ONE).negate();
		BigInteger maxPlusMin = max.add(positiveMin);
		BigInteger number;

		do {
			number = new BigInteger(maxPlusMin.bitLength(), secureRandom);
			number = number.subtract(positiveMin);
		} while ((number.compareTo(max) > 0)
				|| (number.compareTo(negativeMin) < 0)
				|| (number.bitLength() != bitlength));
		return number;
	}

	/**
	 * Computes a multi base exponentiation using a list of bases, over a list of exponents and reduce
	 * each operation by modulo N. Note that the list length of the bases and exponents must match.
	 *
	 * @param bases a list of BigIntegers representing different bases
	 * @param exponents a list of BigIntegers which the bases are to be raised
	 * @param modN modulus N
	 * @return the result of the multi base exponentiation
	 */
	@Override
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

	/**
	 * Computes a multi base exponentiation using a map of bases, over a list of exponents and reduce
	 * each operation by modulo N.
	 *
	 * <p>Note that the list length of the bases and exponents must match.
	 *
	 * @param bases a map of BigIntegers representing different bases
	 * @param exponents a list of BigIntegers which the bases are to be raised
	 * @param modN modulus N
	 * @return the result of the multi base exponentiation
	 * @deprecated
	 */
	@Override
	public BigInteger multiBaseExpMap(
			Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
		GroupElement base;
		BigInteger exponent;

		// This function does not work. There is no guarantee that the two maps are ordered in the same way.
		

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
				result = result.multiply(base.modPow(exponent).getValue()).mod(modN);
			}
		}
		return result;
	}

	/**
	 * Generates a prime number with a minimum and maximum bitlength. The generated prime number is in
	 * range of [2^minBitLength, 2^maxBigLength].
	 *
	 * @param minBitLength the minimum bitlength for the prime number
	 * @param maxBitLength the maximum bitlength for the prime number
	 * @return prime number in range of [2^minBitLength, 2^maxBigLength]
	 */
	@Override
	public BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength) {
		/** TODO check if the implementation is correct for [2^l_e, 2^l_e + 2^lPrime_e] */
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
	 * Generates a prime number in range of a minimum negative integer number and a maximum positive
	 * integer number.
	 *
	 * @param min the minimum integer number
	 * @param max the maximum integer number
	 * @return prime number in range of [-min, +max]
	 */
	@Override
	public BigInteger generatePrimeInRange(BigInteger min, BigInteger max) {
		Assert.notNull(min, "Input minimum was found to be null.");
		Assert.notNull(max, "Input maximum was found to be null.");

		if (min.equals(max)) {
			throw new IllegalArgumentException("Min and max values of the range must be different.");
		}

		log.info("generate prime in range: ");
		BigInteger prime;
		if (min.compareTo(BigInteger.ZERO) < 0) {
			prime = generatePrimeWithNegativeMin(min, max);

		} else {
			prime = generatePrimeWithPositiveMin(min, max);
		}

		return prime;
	}

	private BigInteger generatePrimeWithNegativeMin(BigInteger min, BigInteger max) {
		max = max.subtract(BigInteger.ONE);
		BigInteger positiveMin = min.add(BigInteger.ONE).negate();
		BigInteger negativeMin = min; // TODO Value never used may be a bug!
		BigInteger maxPlusMin = max.add(positiveMin);
		BigInteger prime;

		do {
			prime = new BigInteger(maxPlusMin.bitLength(), secureRandom);
			prime = generateRandomPrime(prime.subtract(positiveMin).bitLength());
		} while ((prime.compareTo(min) < 0) || (prime.compareTo(max) > 0) || !isPrime(prime));

		return prime;
	}

	private BigInteger generatePrimeWithPositiveMin(BigInteger min, BigInteger max) {
		BigInteger prime;
		BigInteger difference = max.subtract(min).add(BigInteger.ONE);

		do {
			BigInteger temp = new BigInteger(difference.bitLength(), secureRandom);
			prime = temp.add(min);
		} while ((prime.compareTo(min) < 0) || (prime.compareTo(max) > 0) || !isPrime(prime));

		return prime;
	}

	/**
	 * Algorithm <tt>alg:generateSpecialRSAModulus</tt> - topocert-doc Computes a special RSA modulus.
	 * Generates random safe primes p and q. The modulus N is computed by multiplying p and q.
	 *
	 * @return an instance of SpecialRSAMod with modulus N and prime factors p and q
	 */
	@Override
	public SpecialRSAMod generateSpecialRSAModulus() {

		p = this.generateRandomSafePrime(KeyGenParameters.getKeyGenParameters());
		q = this.generateRandomSafePrime(KeyGenParameters.getKeyGenParameters());
		modN = p.getSafePrime().multiply(q.getSafePrime());
		return new SpecialRSAMod(modN, p, q);
	}

	/**
	 * Computes a uniformly generated random number in range of a minimum and a maximum BigInteger.
	 *
	 * @param min the minimum BigInteger for the generated random number
	 * @param max the maximum BigInteger for the generated random number
	 * @return a uniformly generated random number in range of [min, max]
	 */
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
			randomNumber = new BigInteger(range.bitLength(), secureRandom);
		} while (randomNumber.compareTo(range) >= 0);

		return randomNumber.add(min);
	}

	/**
	 * Computes a uniformly randomly generated BigInteger with range [0, 2^bitLength - 1].
	 *
	 * <p>Note that this method delegates the construction of the new BigInteger to the BigInteger
	 * constructor.
	 *
	 * @param bitLength the maximum bitLength of the BigInteger
	 * @return BigInteger in range of [0, 2^bitLength - 1]
	 */
	@Override
	public BigInteger createRandomNumber(final int bitLength) {
		return new BigInteger(bitLength, secureRandom);
	}

	/**
	 * Generates a new commitment group.
	 *
	 * <p>We first generate a random prime ρ and then we compute the commitment group modulus Γ using
	 * ρ as input. The next step is to create the generator for the commitment group taking as input
	 * both ρ and Γ.
	 *
	 * <p>We create a random number r in range of [0, ρ] and compute h using the modulus
	 * exponentiation of the commitment group generator g over the random number r and the commitment
	 * group modulus Γ.
	 *
	 * @return a new CommitmentGroup instance constructed with rho, gamma, g and h parameters as
	 *     input.
	 */
	@Override
	public CommitmentGroup generateCommitmentGroup() {

		// TODO check if the computations are correct
		rho = generateRandomPrime(KeyGenParameters.getKeyGenParameters().getL_rho());
		gamma = computeCommitmentGroupModulus(rho);
		g = createCommitmentGroupGenerator(rho, gamma);
		r = createRandomNumber(BigInteger.ZERO, rho);
		h = g.modPow(r, gamma);

		return new CommitmentGroup(rho, gamma, g, h);
	}

	/**
	 * Creates generator for the commitment group.
	 *
	 * @param rho random prime number
	 * @param gamma commitment group modulus
	 * @return generator for the commitment group
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

		} while (!res[1].equals(
				BigInteger.ZERO)); // || gamma.bitLength() != KeyGenParameters.l_gamma.getValue());
		this.primeFactors = primeFactors;
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
	 * <p>This algorithm takes an integer threshold m as input. This algorithm is guaranteed to output
	 * a set uniformly at random chosen prime factors, whose product will be a uniformly-chosen random
	 * number greater than the threshold m.
	 *
	 * <p>The algorithm will output a list of the prime factors of the computed random number.
	 *
	 * <p>Note that the algorithm will call repeatedly to BigInteger.isProbablePrime() tests with the
	 * certainty level specified for the entire library. That means that this method will be
	 * computationally intensive.
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

				if (n.isProbablePrime(KeyGenParameters.getKeyGenParameters().getL_pt())) {
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
	 * <p>This algorithm takes as input an integer threshold m. It will create a uniformly chosen
	 * random prime number (probablePrime) and output the list of its prime factors.
	 *
	 * <p>This method calls the generateRandomNumberWithFactors() method repeatedly, testing the
	 * respective outputs for primeness. While generateRandomNumberWithFactors() is already
	 * computationally intensive, this method is further impacted by repeated primeness tests.
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
			p = p.add(BigInteger.ONE);
		} while (!isPrime(p));

		// TODO check if correct bit length for gamma modulus
		return factors;
	}

	/**
	 * Returns the maximum BigInteger from a list of BigIntegers.
	 *
	 * @param numbers list of BigIntegers
	 * @return the maximum BigInteger
	 */
	public BigInteger getMaxNumber(final ArrayList<BigInteger> numbers) {

		return Collections.max(numbers);
	}

	/**
	 * Algorithm <tt>alg:jacobi_shoup</tt> - topocert-doc
	 *
	 * <p>Compute the Jacobi symbol (a | n). This method delegates the computation of the Jacobi
	 * symbol to the JacobiSymbol class.
	 *
	 * <p>Input: candidate integer a, positive odd integer n Output: Jacobi symbol (a | n). Invariant:
	 * n is odd and positive.
	 *
	 * @param alpha the candidate integer
	 * @param oddNumber the odd integer n
	 * @return Jacobi symbol (a | n)
	 */
	public static int computeJacobiSymbol(final BigInteger alpha, final BigInteger oddNumber) {
		return JacobiSymbol.computeJacobiSymbol(alpha, oddNumber);
	}

	/**
	 * Algorithm <tt>alg:createElementOfZNS</tt> - topocert-doc
	 *
	 * <p>Generate S' number
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
	} // Post-condition: return BigInteger x in [2, N-1], gcd(x, N) = 1

	private boolean isElementOfZNS(final BigInteger s_prime, final BigInteger modN) {
		// check gcd(S', modN) = 1
		return (s_prime.gcd(modN).equals(BigInteger.ONE));
	}

	//  /**
	//   * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc Determines if an integer a is an
	// element
	//   * of QRN
	//   *
	//   * @param alpha candidate integer a
	//   * @param modN positive odd integer (prime factors \( modN: q_1, \ldots , q_r \) )
	//   * @return true if a in QRN, false if a not in QRN Dependencies: jacobiSymbol()
	//   */
	//  @Override
	//  public Boolean elementOfQRN(final BigInteger alpha, final BigInteger modN) {
	//    return (alpha.compareTo(BigInteger.ZERO) > 0)
	//        &&
	// (alpha.compareTo(modN.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue()))
	//            <= 0)
	//        && (JacobiSymbol.computeJacobiSymbol(alpha, modN) == 1);
	//  } // TODO: This function does not seem to match what I was expecting.

	public Boolean elementOfQRN(final BigInteger alpha, final BigInteger modN) {
		return false;
	}

	/**
	 * Algorithm <tt>alg:verifySGeneratorOfQRN_alt</tt> - topocert-doc Evaluate generator S properties
	 * Input: generator S, modulus modN Output: true or false
	 *
	 * @param s the s generator
	 * @param modN
	 * @return true if s is a generator of QRN or else return false
	 */
	public boolean verifySGeneratorOfQRN(final BigInteger s, BigInteger modN) {
		return s.subtract(BigInteger.ONE).gcd(modN).compareTo(BigInteger.ONE) == 0;
	}

	/**
	 * Computes a hash of a list of string using the SHA algorithm with a specified hash length.
	 *
	 * @param list list of string to hash
	 * @param hashLength the length of the hash for the SHA algorithm
	 * @return a BigInteger representing the result of the hash algorithm
	 */
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
	 * Algorithm <tt>alg:power_split</tt> - topocert-doc
	 *
	 * <p>Compute the 2^ha' representation of integer a Input: Odd integer a Output: Integers h and a'
	 * such that a = 2^ha' Post-conditions: a = 2^h a' and a' is odd
	 *
	 * @return the array list
	 */
	public static ArrayList<BigInteger> splitPowerRemainder() {
		return new ArrayList<BigInteger>(2);
	}

	/**
	 * Algorithm <tt>alg:generateCLSignature</tt> - topocert-doc
	 *
	 * <p>Generate Camenisch-Lysyanskaya signature Input: message m Output: signature sigma
	 *
	 * @param m the m
	 * @param base the base representation
	 * @param signerPublicKey the signer's public key
	 * @return the cl signature
	 */
	public GSSignature generateSignature(
			final BigInteger m, final BaseRepresentation base, final SignerPublicKey signerPublicKey) {
		GroupElement A;
		BigInteger e;
		BigInteger v;
		BigInteger modN = signerPublicKey.getModN();
		GroupElement baseS = signerPublicKey.getBaseS();
		GroupElement baseZ = signerPublicKey.getBaseZ();
		GroupElement baseR;
		GroupElement Q;
		BigInteger d;

		int eBitLength =
				(KeyGenParameters.getKeyGenParameters().getL_e() - 1)
				+ (KeyGenParameters.getKeyGenParameters().getL_prime_e() - 1);
		e =
				CryptoUtilsFacade.computePrimeWithLength(
						KeyGenParameters.getKeyGenParameters().getL_e() - 1, eBitLength);
		v = CryptoUtilsFacade.computeRandomNumber(KeyGenParameters.getKeyGenParameters().getL_v() - 1);

		baseR = base.getBase().modPow(m);

		/** TODO check if the computations for generating the cl-signature are correct */
		GroupElement invertible = baseS.modPow(v).multiply(baseR);
		Q = baseZ.multiply(invertible.modInverse());
		A = Q.modPow(e.modInverse(modN));

		return new GSSignature(signerPublicKey, A, e, v);
	}

	/**
	 * Algorithm <tt>alg:generateRandomSafePrime</tt> - topocert-doc
	 *
	 * <p>Generate Random Safe Prime Input: l_n bit-length, l_pt Output: safe prime p, Sophie Germain
	 * p'
	 */
	@Override
	public SafePrime generateRandomSafePrime(KeyGenParameters keyGenParameters) {

		BigInteger a;
		BigInteger a_prime;

		do {
			a_prime = generateRandomPrime((keyGenParameters.getL_n() / 2) - 1);
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
	public Boolean isPrime(final BigInteger number) {
		Assert.notNull(number, "Number to be checked was found to be null.");
		Assert.notNull(KeyGenParameters.getKeyGenParameters(), "KeyGenParameters was null.");
		Assert.notNull(
				KeyGenParameters.getKeyGenParameters().getL_pt(), "Primality check likelihood was null.");
		return number.isProbablePrime(KeyGenParameters.getKeyGenParameters().getL_pt());
	}

	/**
	 * Generate prime big integer with bitLength.
	 *
	 * @param bitLength length of prime number
	 * @return the big integer
	 */
	public BigInteger generateRandomPrime(final int bitLength) {
		return BigInteger.probablePrime(bitLength, secureRandom);
	}

	/**
	 * Returns the upper bound of a +/- BigInteger, that is, <tt>+2^(bitLength)-1</tt>.
	 *
	 * <p>Internally, the method stores bounds and only computes exponentiations once.
	 *
	 * @param bitLength a positive int
	 * @return BigInteger upper bound
	 */
	public BigInteger getUpperPMBound(final int bitLength) {
		if (bitLength <= 0) throw new RuntimeException("BitLength must be positive.");

		Integer iBitLength = new Integer(bitLength);
		if (boundMap.containsKey(iBitLength)) {
			return boundMap.get(iBitLength);
		} else {
			BigInteger upperBound =
					(NumberConstants.TWO.getValue().pow(bitLength)).subtract(BigInteger.ONE);
			boundMap.put(iBitLength, upperBound);
			return upperBound;
		}
	}

	/**
	 * Returns the lower bound of a +/- BigInteger, that is, <tt>-2^(bitLength)+1</tt>.
	 *
	 * <p>Internally, the method stores bounds and only computes exponentiations once.
	 *
	 * @param bitLength a positive int
	 * @return BigInteger lower bound
	 */
	public BigInteger getLowerPMBound(final int bitLength) {
		if (bitLength <= 0) throw new RuntimeException("BitLength must be positive.");

		Integer iBitLength = new Integer(-bitLength);
		if (boundMap.containsKey(iBitLength)) {
			return boundMap.get(iBitLength);
		} else {
			BigInteger lowerBound =
					((NumberConstants.TWO.getValue().pow(bitLength)).negate()).add(BigInteger.ONE);
			boundMap.put(iBitLength, lowerBound);
			return lowerBound;
		}
	}

	/**
	 * Checks whether a BigInteger argument is in the correct +/- range.
	 *
	 * @param number to be tested for correct range
	 * @param bitLength length of the +/- BigInteger
	 * @return <tt>true</tt> if the BigInteger number is in the range <tt>[-2^(bitLength)+1 ...
	 *     2^(bitLength)-1]</tt>
	 */
	public boolean isInPMRange(final BigInteger number, final int bitLength) {
		if (number == null) {
			return false;
		}

		BigInteger max = getUpperPMBound(bitLength);
		BigInteger min = getLowerPMBound(bitLength);

		return isInRange(number, min, max);
	}

	/**
	 * Checks whether a BigInteger number is in the correct range of a minimum and maximum number
	 *
	 * @param number to be tested for correct range
	 * @param min the mininum number in range
	 * @param max the maximum number in range
	 * @return <tt>true</tt> if the BigInteger number is in the range of <tt>[min, max]</tt>
	 */
	public boolean isInRange(BigInteger number, BigInteger min, BigInteger max) {
		if (number == null) {
			return false;
		}
		Assert.notNull(min, "isInRange received a min that is null.");
		Assert.notNull(max, "isInRange received a max that is null.");
		return (number.compareTo(min) >= 0) && (number.compareTo(max) <= 0);
	}

	/**
	 * Returns the single GroupElement of a singleton result map of a computation.
	 *
	 * @param map singleton map, that is, Map with only one element.
	 * @return GroupElement encapsulated by the map
	 */
	public GroupElement getSingletonMapGroupElement(Map<URN, GroupElement> map) {
		Assert.notNull(map, "GroupElement map submitted for extraction was null.");
		if (map.isEmpty() || map.size() > 1) {
			throw new IllegalArgumentException("Submitted argument is not a singleton map.");
		}
		// Post-Condition: Map is non-null and has exactly one element.
		GroupElement result = null;
		Iterator<GroupElement> iter = map.values().iterator();
		while (iter.hasNext()) {
			result = (GroupElement) iter.next();
		}
		return result;
	}

	/**
	 * Computes a multi-base exponentiation over ALL bases of a BaseCollection. Naturally the method
	 * treats bases with null exponent as 1.
	 *
	 * @param collection BaseCollection to iterate over.
	 * @param G A Group to work in.
	 * @return Product of the exponentiations.
	 */
	@Override
	public GroupElement computeMultiBaseExp(BaseCollection collection, Group G) {
		return computeMultiBaseExp(collection, BASE.ALL, G);
	}

	/**
	 * Computes a multi-base exponentiation over a type of bases of a BaseCollection. Naturally the
	 * method treats bases with null exponent as 1.
	 *
	 * @param collection BaseCollection to iterate over.
	 * @param baseType type of base to include.
	 * @param G A Group to work in.
	 * @return Product of the exponentiations.
	 */
	@Override
	public GroupElement computeMultiBaseExp(BaseCollection collection, BASE baseType, Group G) {
		GroupElement result = G.getOne();
		BaseIterator baseIter = collection.createIterator(baseType);
		while (baseIter.hasNext()) {
			BaseRepresentation base = (BaseRepresentation) baseIter.next();
			if (base.getBase() != null && base.getExponent() != null) {
				result = result.multiply(base.getBase().modPow(base.getExponent()));
			}
		}
		return result;
	}
}
