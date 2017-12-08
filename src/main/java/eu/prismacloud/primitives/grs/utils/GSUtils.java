package eu.prismacloud.primitives.grs.utils;

import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.logging.Logger;


public class GSUtils implements INumberUtils {
    private static final Logger log = Logger.getLogger(GSUtils.class.getName());

    //      private static BigInteger p;
//      private final BigInteger p_prime;
//      private final BigInteger q = null;
//      private final BigInteger q_prime = null;
    private static BigInteger n = null;
    private static SafePrime p;
    private static SafePrime q;
    private BigInteger rho;
    private BigInteger gamma;
    private BigInteger g;
    private BigInteger r;
    private BigInteger h;

    protected GSUtils() {
    }


    /**
     * Algorithm 1 - topocert-doc
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


    @Override
    public BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
        return null;
    }

    @Override
    public CommitmentGroup generateCommitmentGroup() {
        rho = generatePrime(KeyGenParameters.l_rho.getValue());
        gamma = generateGroupModulus(rho);
        g = createGenerator(rho, gamma);
        r = createRandomNumber(BigInteger.ZERO, rho);
        h = bigPow(g, r);
        return new CommitmentGroup(rho, gamma, g, h);
    }

    private BigInteger createGenerator(BigInteger rho, BigInteger gamma) {
        return new BigInteger("1");
    }


    /**
     * Calculates BigInteger exponentiations
     *
     * @param base the base
     * @param e    the exponent
     * @return 
     */
    public BigInteger bigPow(BigInteger base, BigInteger e) {
        if (e.compareTo(BigInteger.ZERO) < 0)
            throw new IllegalArgumentException("exponent must not be negative");
        BigInteger temp = base;
        BigInteger b = BigInteger.ONE;

        byte[] bytes = e.toByteArray();


        for (int i = bytes.length - 1; i >= 0; i--) {
            byte bit = bytes[i];
            for (int j = 0; j < 8; j++) {
                if ((bit & 1) != 0)
                    b = b.multiply(temp);
                
                bit = (byte) (bit >> 1);
                log.info("shift: " + bit + " for i: " + i + " for j: " + j );
                // discard rest of bits
//              if ((bits == 0) && i == 0)
//                    return b;
                temp = temp.multiply(temp);
            }
        }


        return b;


    }


//    public static BigInteger bigPow(BigInteger x, BigInteger y) {
//      if (y.compareTo(BigInteger.ZERO) < 0)
//        throw new IllegalArgumentException();
//      BigInteger z = x; // z will successively become x^2, x^4, x^8, x^16, x^32...
//      BigInteger result = BigInteger.ONE;
//      byte[] bytes = y.toByteArray();
//      for (int i = bytes.length - 1; i >= 0; i--) {
//        byte bits = bytes[i];
//        for (int j = 0; j < 8; j++) {
//          if ((bits & 1) != 0)
//            result = result.multiply(z);
//          // short cut out if there are no more bits to handle:
//          if ((bits >>= 1) == 0 && i == 0)
//            return result;
//          z = z.multiply(z);
//        }
//      }
//      return result;
//    }

    private BigInteger generateGroupModulus(BigInteger rho) {

        return new BigInteger("1");
    }


    /**
     * Algorithm 2 - topocert-doc
     * Compute the Jacobi symbol (A | N)
     * Input: candidate integer a, positive odd integer N
     * Output: Jacobi symbol (a | N)
     * Invariant: N is odd and positive
     * Dependencies: splitPowerRemainder()
     */
    public static int computeJacobiSymbol(BigInteger alpha, BigInteger N) {
        return JacobiSymbol.computeJacobiSymbol(alpha,N);
    }


    /**
     * Algorithm 3 - topocert-doc
     * Determines if an integer  a is an element of QRN
     * Input: candidate integer a, prime factors of positive, odd integer N: q_1, ..., q_r
     * Output: true if a in QRN, false if a not in QRN
     * Dependencies: jacobiSymbol()
     */

    public static Boolean elementOfQR() {
        return true;
    }

    /**
     * Algorithm 4 - topocert-doc
     * Generate S' number
     * Input: Special RSA modulus N
     * Output: random number S' of QRN
     * Dependencies: isElementOfZNS()
     */

    public BigInteger createElementOfZNS() {

        BigInteger s_prime;
        do {

            s_prime = createRandomNumber(NumberConstants.TWO.getValue(), n.subtract(BigInteger.ONE));

        } while (!isElementOfZNS(s_prime));

        return s_prime;
    }

    private static boolean isElementOfZNS(BigInteger s_prime) {
        // check gcd(S', N) = 1
        return (s_prime.gcd(n).equals(BigInteger.ONE));
    }


    /**
     * Algorithm 5 - topocert-doc
     * Evaluate generator S properties
     * Input: generator S, p', q'
     * Output: true or false
     */
    public static Boolean verifySGeneratorOfZNS(BigInteger s) {
        return true;
    }

    /**
     * Algorithm 6 - topocert-doc
     * Create generator of QRN
     * Input: Special RSA modulus N, p', q'
     * Output: generator S of QRN
     * Dependencies: createElementOfZNS(), verifySGenerator()
     */
    public BigInteger createQRNGenerator(BigInteger n) {

        BigInteger s;
        BigInteger s_prime;

        do {

            s_prime = createElementOfZNS();
            s = s_prime.modPow(NumberConstants.TWO.getValue(), n);


        } while (!verifySGeneratorOfZNS(s));
        return new BigInteger("1");
    }


    /**
     * Algorithm 7 - topocert-doc
     * Compute the 2^ha' representation of integer a
     * Input: Odd integer a
     * Output: Integers h and a' such that a = 2^ha'
     * Post-conditions: a = 2^ha' and a' is odd
     */

    public static ArrayList<BigInteger> splitPowerRemainder() {
        return new ArrayList<BigInteger>(2);
    }


    /**
     * Algorithm 8 - topocert-doc
     * Generate Camenisch-Lysyanskaya signature
     * Input: message m
     * Output: signature sigma
     */

    public static CLSignature generateCLSignature(CLMessage m) {
        return new CLSignature();
    }


    /**
     * Algorithm 9 - topocert-doc
     * Generate Signature Proof of Knowledge
     * Input: R_0,S, Z, N
     * Output: signature proof of knowledge SPK
     */

    public static SPoK generateSignatureProofOfKnowledge() {
        return new SPoK();
    }

    /**
     * Algorithm 2 - topocert-doc
     * Generate Random Safe Prime
     * Input: l_n bit-length, l_pt
     * Output: safe prime p, Sophie Germain p'
     */
    public SafePrime generateRandomSafePrime() {
        BigInteger a = null;
        BigInteger a_prime = null;
        do {

            a_prime = generatePrime(KeyGenParameters.l_n.getValue() / 2);
            log.info("a_prime: " + a_prime);
            a = new BigInteger("2").multiply(a_prime).add(BigInteger.valueOf(1));
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
     * Generate prime big integer.
     *
     * @return the big integer
     */
    public static BigInteger generatePrime(int bitLength) {

        BigInteger a = Utils.genPrime(KeyGenParameters.l_n.getValue() / 2, KeyGenParameters.l_pt.getValue());
        return a;
    }
}
