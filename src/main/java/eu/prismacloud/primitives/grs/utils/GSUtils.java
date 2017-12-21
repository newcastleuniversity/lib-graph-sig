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


    @Override
    public BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
        return null;
    }

    @Override
    public CommitmentGroup generateCommitmentGroup() {
        // TODO check if the computations are correct
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
     * Algorithm <tt>alg:computeBigPow</tt> - topocert-doc
     * Calculates BigInteger exponentiations
     *
     * @param base the base
     * @param e    the exponent
     * @return b \( base^e \)
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
                //log.info("shift: " + bit + " for i: " + i + " for j: " + j );
                // discard rest of bits
//              if ((bits == 0) && i == 0)
//                    return b;
                temp = temp.multiply(temp);
            }
        }

        return b;

    }


    private BigInteger generateGroupModulus(BigInteger rho) {

        return new BigInteger("1");
    }


    /**
     * Algorithm <tt>alg:jacobi_shoup</tt> - topocert-doc
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
     * Algorithm <tt>alg:element_of_QR_N</tt> - topocert-doc
     * Determines if an integer  a is an element of QRN
     * Input: candidate integer a, prime factors of positive, odd integer N: q_1, ..., q_r
     * Output: true if a in QRN, false if a not in QRN
     * Dependencies: jacobiSymbol()
     */

    public Boolean elementOfQR(BigInteger value, BigInteger modulus)
    {
        return value.compareTo(BigInteger.ZERO) > 0 && value.compareTo(modulus.subtract(BigInteger.ONE).divide(NumberConstants.TWO.getValue())) <= 0
                        && JacobiSymbol.computeJacobiSymbol(value, modulus) == 1;
    }

    /**
     * Algorithm <tt>alg:createElementOfZNS</tt> - topocert-doc
     * Generate S' number
     * Input: Special RSA modulus N
     * Output: random number S' of QRN
     * Dependencies: isElementOfZNS()
     * @param n
     */

    public BigInteger createElementOfZNS(BigInteger n) {

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
     * Algorithm <tt>alg:verifySGeneratorOfZNS</tt> - topocert-doc
     * Evaluate generator S properties
     * Input: generator S, p', q'
     * Output: true or false
     */
    public static Boolean verifySGeneratorOfZNS(BigInteger s) {
        return true;
    }

    /**
     * Algorithm <tt>alg:generator_QR_N</tt> - topocert-doc
     * Create generator of QRN
     * Input: Special RSA modulus N, p', q'
     * Output: generator S of QRN
     * Dependencies: createElementOfZNS(), verifySGenerator()
     */
    public BigInteger createQRNGenerator(BigInteger n) {

        BigInteger s;
        BigInteger s_prime;

        do {

            s_prime = createElementOfZNS(n);
            s = s_prime.modPow(NumberConstants.TWO.getValue(), n);


        } while (!verifySGeneratorOfZNS(s));
        return new BigInteger("1");
    }


    /**
     * Algorithm <tt>alg:power_split</tt> - topocert-doc
     * Compute the 2^ha' representation of integer a
     * Input: Odd integer a
     * Output: Integers h and a' such that a = 2^ha'
     * Post-conditions: a = 2^h a' and a' is odd
     */

    public static ArrayList<BigInteger> splitPowerRemainder() {
        return new ArrayList<BigInteger>(2);
    }


    /**
     * Algorithm <tt>alg:generateCLSignature</tt> - topocert-doc
     * Generate Camenisch-Lysyanskaya signature
     * Input: message m
     * Output: signature sigma
     */

    public static CLSignature generateCLSignature(CLMessage m) {
        return new CLSignature();
    }


    /**
     * Algorithm <tt>alg:generateSigProof</tt> - topocert-doc
     * Generate Signature Proof of Knowledge
     * Input: R_0,S, Z, N
     * Output: signature proof of knowledge SPK
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
        BigInteger a = BigInteger.ONE;
        BigInteger a_prime = BigInteger.ONE;
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
