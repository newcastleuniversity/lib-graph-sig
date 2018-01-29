package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.logging.Logger;

/**
 * Crypto Utilities class for graph signature library
 */
public class GSUtils implements INumberUtils {

    private static final Logger log = Logger.getLogger(GSUtils.class.getName());
    private BigInteger n;
    private SafePrime p;
    private SafePrime q;
    private BigInteger rho;
    private BigInteger gamma;
    private BigInteger g;
    private BigInteger r;
    private BigInteger h;
    private ArrayList<BigInteger> primeFactors;

    protected GSUtils() {
    }


    /**
     * Algorithm <tt>alg:generateSpecialRSAModulus</tt> - topocert-doc
     * Generate Special RSA Modulus N
     * Input: candidate integer a, prime factors of positive, odd integer N: q_1, ..., q_r
     * Output: N,p,q,p',q'
     * \(N = p * q \)
     */
    public SpecialRSAMod generateSpecialRSAModulus() {
        p = this.generateRandomSafePrime();
        q = this.generateRandomSafePrime();
        n = p.getSafePrime().multiply(q.getSafePrime());
        return new SpecialRSAMod(n, p, q);
    }


    // @Override
    public BigInteger createRandomNumber(BigInteger min, BigInteger max) {

        BigInteger randomNumber, result, range, temp;

        if (max.compareTo(min) < 0) {
            temp = min;
            min = max;
            max = temp;
        } else if (max.compareTo(min) == 0) {
            return min;
        }

        //range =  max - min + 1
        range = max.subtract(min).add(BigInteger.ONE);
        //   log.info("range: " + range);

        do {
            randomNumber = new BigInteger(range.bitLength(), new SecureRandom());
        } while (randomNumber.compareTo(range) >= 0);

        //   log.info("random: " + randomNumber);
        result = randomNumber.add(min);
        return result;
    }

    @Override
    public CommitmentGroup generateCommitmentGroup() {
        // TODO check if the computations are correct
        rho = generatePrime(KeyGenParameters.l_rho.getValue());
        gamma = computeCommitmentGroupModulus(rho);
        g = createCommitmentGroupGenerator(rho, gamma);
        r = createRandomNumber(BigInteger.ZERO, rho);
        h = g.modPow(r, gamma);
        return new CommitmentGroup(rho, gamma, g, h);
    }


    /**
     * Create generator for commitment group
     * @param rho
     * @param gamma
     * @return
     */
    @Override
    public BigInteger createCommitmentGroupGenerator(final BigInteger rho, final BigInteger gamma) {
        BigInteger exp, g, h;
        exp = gamma.subtract(BigInteger.ONE).divide(rho);

        do {
            h = createRandomNumber(NumberConstants.TWO.getValue(), gamma);
            log.info("h: " + h);
            g = h.modPow(exp, gamma);
            log.info("g: " + g);

        } while (h.equals(BigInteger.ONE));

        return g;
    }

    /**
     * Algorithm <tt>alg:zps_gen</tt> - topocert-doc
     * 
     * Create generator for \( Z^*_\Gamma \).
     *
     * @param gamma        the gamma modulus
     * @param primeFactors the prime factors
     * @return generator for \( Z^*_\Gamma \)
     */
    public BigInteger createZPSGenerator(BigInteger gamma, ArrayList<BigInteger> primeFactors) {
        // TODO check if current algorithm is correct
        BigInteger alpha, beta, g = BigInteger.ONE;
        
        ArrayList<BigInteger> genFactors = new ArrayList<BigInteger>();

        for (BigInteger factor : primeFactors) {
            log.info("factor: " + factor);
            do {

//              alpha = generatePrime(KeyGenParameters.l_gamma.getValue());
                alpha = createRandomNumber(BigInteger.ONE, gamma.subtract(BigInteger.ONE));
//                log.info("alpha: " + alpha);
                
                beta = alpha.modPow(factor, gamma);
                log.info("beta: " + beta);

            } while (beta.equals(BigInteger.ONE));// || !beta.equals(BigInteger.valueOf(0)));
            log.info("alpha: " + alpha);
            genFactors.add(alpha.modPow(factor,gamma));

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
            log.info("remainder 1: " + res[1]);

        }
        while (!res[1].equals(BigInteger.ZERO));// || gamma.bitLength() != KeyGenParameters.l_gamma.getValue());
        this.primeFactors = primeFactors;
        log.info("gamma: " + gamma);
        return gamma;

    }

    public BigInteger getRho() {
        return this.rho;
    }

    public ArrayList<BigInteger> getPrimeFactors(){
        return this.primeFactors;
    }

    /**
     * Algorithm <tt>alg:gen_numb_fact</tt> - topocert-doc
     * Generate random number in factored form.
     *
     * @param m integer number \(m \geq 2 \)
     * @return prime number factorization \(p_1, \ldots, p_r \)
     */
    public ArrayList<BigInteger> generateRandomNumberWithFactors(BigInteger m) {

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

                //  log.info("n " + n);

                if (n.isProbablePrime(KeyGenParameters.l_pt.getValue())) {
                    primeSeq.add(n);
                    y = y.multiply(n);
                }

            } while (n.compareTo(min) > 0);

            x = createRandomNumber(BigInteger.ONE, m);

            //  log.info("y prime :  " + y);
            //   log.info("isPrime:  " + isPrime(y));

        } while (y.compareTo(m) <= 0 && x.compareTo(y) <= 0);

        //  log.info("y: " + y);

        return primeSeq;
    }


    /**
     * Algorithm <tt>alg:gen_prime_numb_fact</tt> - topocert-doc
     * Generate random prime number along with its factorization.
     *
     * @param m integer number \( m \geq 2 \)
     * @return prime number factorization \(p_1, \ldots, p_r \) of a prime number
     */
    public ArrayList<BigInteger> generateRandomPrimeWithFactors(BigInteger m) {

        ArrayList<BigInteger> factors;
        BigInteger p;

        do {

            p = BigInteger.ONE;
            factors = generateRandomNumberWithFactors(m);

            //  log.info("rnd length: " + factors.size());

            for (BigInteger factor : factors) {
                //        log.info("factor " + i + " : " + factor);
                p = p.multiply(factor);
            }
            //    log.info("p: " + p.add(BigInteger.ONE));
            //    log.info("p: bitlength " + p.add(BigInteger.ONE).bitLength());
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
    public BigInteger getMaxNumber(ArrayList<BigInteger> numbers) {

        return Collections.max(numbers);
    }

    /**
     * Algorithm <tt>alg:jacobi_shoup</tt> - topocert-doc
     * Compute the Jacobi symbol (A | N)
     * Input: candidate integer a, positive odd integer N
     * Output: Jacobi symbol (a | N)
     * Invariant: N is odd and positive
     * Dependencies: splitPowerRemainder()
     *
     * @param alpha the alpha
     * @param N     the n
     * @return the int
     */
    public static int computeJacobiSymbol(final BigInteger alpha, final BigInteger N) {
        return JacobiSymbol.computeJacobiSymbol(alpha, N);
    }


    /**
     * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc
     * Determines if an integer  a is an element of QRN
     *
     * @param alpha candidate integer a
     * @param N     positive odd integer (prime factors \( N: q_1, \ldots , q_r \) )
     * @return true if a in QRN, false if a not in QRN
     * Dependencies: jacobiSymbol()
     */

    public Boolean elementOfQRN(final BigInteger alpha, final BigInteger N) {
        return alpha.compareTo(BigInteger.ZERO) > 0 && alpha.compareTo(N.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue())) <= 0
                && JacobiSymbol.computeJacobiSymbol(alpha, N) == 1;
    }

    /**
     * Algorithm <tt>alg:createElementOfZNS</tt> - topocert-doc
     * Generate S' number
     * <p>
     * Dependencies: isElementOfZNS()
     *
     * @param N the special RSA modulus
     * @return s_prime random number S' of QRN
     */
    public BigInteger createElementOfZNS(final BigInteger N) {

        BigInteger s_prime;
        do {

            s_prime = createRandomNumber(NumberConstants.TWO.getValue(), n.subtract(BigInteger.ONE));

        } while (!isElementOfZNS(s_prime, N));

        return s_prime;
    }

    private boolean isElementOfZNS(final BigInteger s_prime, final BigInteger N) {
        // check gcd(S', N) = 1
        return (s_prime.gcd(this.n).equals(BigInteger.ONE));
    }


    /**
     * Algorithm <tt>alg:verifySGeneratorOfQRN</tt> - topocert-doc
     * Evaluate generator S properties
     * Input: generator S, p', q'
     * Output: true or false
     *
     * @param s the s
     * @return the boolean
     */
    public static Boolean verifySGeneratorOfQRN(final BigInteger s) {
        return true;
    }

    /**
     * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc
     * Create generator of QRN
     * Input: Special RSA modulus N, p', q'
     * Output: generator S of QRN
     * Dependencies: createElementOfZNS(), verifySGenerator()
     */
    public BigInteger createQRNGenerator(final BigInteger n) {

        BigInteger s;
        BigInteger s_prime;

        do {

            s_prime = createElementOfZNS(n);
            s = s_prime.modPow(NumberConstants.TWO.getValue(), n);

        } while (!verifySGeneratorOfQRN(s));
        return new BigInteger("1");
    }


    /**
     * Algorithm <tt>alg:power_split</tt> - topocert-doc
     * Compute the 2^ha' representation of integer a
     * Input: Odd integer a
     * Output: Integers h and a' such that a = 2^ha'
     * Post-conditions: a = 2^h a' and a' is odd
     *
     * @return the array list
     */
    public static ArrayList<BigInteger> splitPowerRemainder() {
        return new ArrayList<BigInteger>(2);
    }


    /**
     * Algorithm <tt>alg:generateCLSignature</tt> - topocert-doc
     * Generate Camenisch-Lysyanskaya signature
     * Input: message m
     * Output: signature sigma
     *
     * @param m the m
     * @return the cl signature
     */
    public static CLSignature generateCLSignature(CLMessage m) {
        return new CLSignature();
    }


    /**
     * Algorithm <tt>alg:generateSigProof</tt> - topocert-doc
     * Generate Signature Proof of Knowledge
     * Input: R_0,S, Z, N
     * Output: signature proof of knowledge SPK
     *
     * @return the s po k
     */
    public static SPoK generateSignatureProofOfKnowledge() {
        return new SPoK();
    }

    /**
     * Algorithm <tt>alg:generateRandomSafePrime</tt> - topocert-doc
     * Generate Random Safe Prime
     * Input: l_n bit-length, l_pt
     * Output: safe prime p, Sophie Germain p'
     */
    public SafePrime generateRandomSafePrime() {
        BigInteger a;
        BigInteger a_prime;

        do {

            a_prime = generatePrime(KeyGenParameters.l_n.getValue() / 2);
            log.info("a_prime: " + a_prime);
            a = NumberConstants.TWO.getValue().multiply(a_prime).add(BigInteger.ONE);
            log.info("a: " + a);
            log.info("isPrime: " + isPrime(a));

        } while (!isPrime(a));
        return new SafePrime(a, a_prime);
    }

    /**
     * Is prime boolean.
     *
     * @param number the number
     * @return the boolean
     */
    public static Boolean isPrime(BigInteger number) {
        return number.isProbablePrime(KeyGenParameters.l_pt.getValue());
    }

    /**
     * Generate prime big integer with bitLength.
     *
     * @param bitLength length of prime number
     * @return the big integer
     */
    public static BigInteger generatePrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, new SecureRandom());
    }
}
