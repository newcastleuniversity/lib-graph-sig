package eu.prismacloud.primitives.grs.utils;

import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
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
    public BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
        // TODO refactor for creating a random number in range min, max
        return new BigInteger(upperBound.bitLength(), new SecureRandom());
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


    @Override
    public BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma) {
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
     * Compute group modulus for the commitment group.
     *
     * @param rho prime number
     * @return gamma commitment group modulus
     */
    public BigInteger computeCommitmentGroupModulus(final BigInteger rho) {

        int l_b = KeyGenParameters.l_gamma.getValue() - rho.bitLength();
        BigInteger b;
        BigInteger[] res;

        do {

            do {

                b = new BigInteger(l_b, new SecureRandom());
                // TODO refactor to computeRandomNumber for b > 0
                if (b.equals(BigInteger.ZERO)) break;

                gamma = rho.multiply(b).add(BigInteger.ONE);
//                log.info("gamma: " + gamma);

            } while (!gamma.isProbablePrime(KeyGenParameters.l_pt.getValue()));

            // rho divides gamma - 1
            res = gamma.subtract(BigInteger.ONE).divideAndRemainder(rho);
            log.info("remainder 1: " + res[1]);

        }
        while (!res[1].equals(BigInteger.ZERO) || gamma.bitLength() != KeyGenParameters.l_gamma.getValue());

        log.info("gamma: " + gamma);
        return gamma;

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
    public static int computeJacobiSymbol(BigInteger alpha, BigInteger N) {
        return JacobiSymbol.computeJacobiSymbol(alpha, N);
    }


    /**
     * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc
     * Determines if an integer  a is an element of QRN
     * 
     * @param alpha candidate integer a
     * @param N positive odd integer (prime factors \( N: q_1, \ldots , q_r \) )
     * @return true if a in QRN, false if a not in QRN
     * Dependencies: jacobiSymbol()
     */

    public Boolean elementOfQR(BigInteger alpha, BigInteger N) {
        return alpha.compareTo(BigInteger.ZERO) > 0 && alpha.compareTo(N.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue())) <= 0
                && JacobiSymbol.computeJacobiSymbol(alpha, N) == 1;
    }

    /**
     * Algorithm <tt>alg:createElementOfQRN</tt> - topocert-doc
     * Generate S' number
     * Input: Special RSA modulus N
     * Output: random number S' of QRN
     * Dependencies: isElementOfZNS()
     *
     * @param n the n
     * @return the big integer
     */
    public BigInteger createElementOfQRN(BigInteger n) {

        BigInteger s_prime;
        do {

            s_prime = createRandomNumber(NumberConstants.TWO.getValue(), n.subtract(BigInteger.ONE));

        } while (!isElementOfZNS(s_prime));

        return s_prime;
    }

    private boolean isElementOfZNS(BigInteger s_prime) {
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
    public static Boolean verifySGeneratorOfQRN(BigInteger s) {
        return true;
    }

    /**
     * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc
     * Create generator of QRN
     * Input: Special RSA modulus N, p', q'
     * Output: generator S of QRN
     * Dependencies: createElementOfQRN(), verifySGenerator()
     */
    public BigInteger createQRNGenerator(BigInteger n) {

        BigInteger s;
        BigInteger s_prime;

        do {

            s_prime = createElementOfQRN(n);
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
