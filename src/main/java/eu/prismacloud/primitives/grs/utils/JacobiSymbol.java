package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Jacobi Symbol
 */
public class JacobiSymbol {

    private static int sigma;
    private static BigInteger h;
    private static BigInteger alpha_prime;
    //private static GSUtils gs;
    private static GSUtils gs = new GSUtils();

    private JacobiSymbol() {
    }


    /**
     * Compute the jacobiSymbol based on
     * <tt>alg:jacobi_shoup</tt> in topocert-doc
     *
     * @param alpha candidate integer
     * @param N     positive odd integer
     * @return jacobi symbol (a|N)
     */
    public static int computeJacobiSymbol(BigInteger alpha, BigInteger N) {
        if (alpha == null) {
            throw new IllegalArgumentException("A value for alpha is needed.");
        }
        if (N == null) {
            throw new IllegalArgumentException("A value for N is needed.");
        }
        if (N.compareTo(NumberConstants.TWO.getValue()) <= 0) {
            throw new IllegalArgumentException("Use an odd integer.");
        }

        sigma = 1;
        do {
            alpha = alpha.mod(N);

            if (alpha.equals(BigInteger.ZERO)) {

                if (N.equals(BigInteger.ONE))
                    return sigma;
                else return 0;
            }
            splitPowerRemainder(alpha);

            if (!h.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO) && (!N.mod(NumberConstants.EIGHT.getValue()).equals(BigInteger.ONE))) {

                return sigma = -1;

            }

            if (!alpha_prime.mod(new BigInteger("4")).equals(BigInteger.ONE) && (!N.mod(NumberConstants.FOUR.getValue()).equals(BigInteger.ONE))) {
                return sigma = -1;
            }


        } while (N.compareTo(NumberConstants.TWO.getValue()) > 0);


        return 1;
    }

    /**
     * Computes the greatest power of base 2 contained in an odd integer a and its remainder a'
     * based on <tt>alg:power_split</tt> in topocert-doc
     *
     * @param alpha odd integer
     * @return alpha_prime remainder
     */
    public static BigInteger splitPowerRemainder(BigInteger alpha) {
        h = BigInteger.valueOf(alpha.bitLength()).subtract(BigInteger.ONE);

        gs.bigPow(NumberConstants.TWO.getValue(), h);
        alpha_prime = alpha.subtract(gs.bigPow(NumberConstants.TWO.getValue(), h));
        // TODO refactor return (h,a')
        return alpha_prime;

    }

    static int j;

    /**
     * Compute Jacobi symbol based on
     * Algorithm 1.4 in "Cryptography made simple" book
     *
     * @param b
     * @param a
     * @return
     */
    public static int computeJacobiSymbolBA(BigInteger a, BigInteger b) {
        // b<= 0 or b (mod 2) = 0

       boolean k = b.compareTo(BigInteger.ZERO) <= 0 ;
       boolean o = b.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO);
       BigInteger temp;
       
        if (b.compareTo(BigInteger.ZERO) <= 0 || b.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO))
            return 0;
        
        j = 1;

        if (a.compareTo(BigInteger.ZERO) < 0) {
            a = a.negate();

            // b (mod 4) = 3
            if (b.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue())) {
                j = -j;
            }
        }

        while (a.compareTo(BigInteger.ZERO) != 0) {

            // a (mod 2) = 0
            while (a.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO)) {
                
                // a = a/2
                a = a.divide(NumberConstants.TWO.getValue());

                // b (mod 8) = 3 or b (mod 8) = 5
                if (b.mod(NumberConstants.EIGHT.getValue()).equals(NumberConstants.THREE.getValue()) || b.mod(NumberConstants.EIGHT.getValue()).equals(NumberConstants.FIVE.getValue())) {
                    j = -j;
                }

            }

            temp = a;
            a = b;
            b = temp;

            // a (mod 4) = 3 and b (mod 4) = 3
            if (a.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue()) && b.mod(NumberConstants.FOUR.getValue()).equals(NumberConstants.THREE.getValue())) {
                j = -j;
            }

            a = a.mod(b);

        }
        if (b.equals(BigInteger.ONE))
            return j;
        else
            return 0;

    }

}
