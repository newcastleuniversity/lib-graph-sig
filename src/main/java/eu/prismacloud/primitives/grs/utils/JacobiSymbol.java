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
     * Compute the jacobiSymbol
     * @param alpha candidate integer
     * @param N positive odd integer
     * @return jacobi symbol (a|N)
     */
    public static int computeJacobiSymbol(BigInteger alpha,  BigInteger N) {
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
        do{
            alpha  = alpha.mod(N);

            if (alpha.equals(BigInteger.ZERO)) {

                if (N.equals(BigInteger.ONE))
                    return sigma;
                else return 0;
            }
            splitPowerRemainder(alpha);

            if (!h.mod(NumberConstants.TWO.getValue()).equals(BigInteger.ZERO) && (!N.mod(new BigInteger("8")).equals(BigInteger.ONE)) ){

                return  sigma = -1;

            }

            if (!alpha_prime.mod(new BigInteger("4")).equals(BigInteger.ONE) && (!N.mod(new BigInteger("4")).equals(BigInteger.ONE))){
                return sigma = -1;
            }
        




        } while (N.compareTo(NumberConstants.TWO.getValue()) > 0);




        return 1;
    }

    /**
     * @param alpha
     */
    private static void splitPowerRemainder(BigInteger alpha) {
        //TODO check if this is correct 
      h = BigInteger.valueOf(alpha.bitLength());

      gs.bigPow(NumberConstants.TWO.getValue(), h);
      alpha_prime = alpha.subtract(gs.bigPow(NumberConstants.TWO.getValue(), h));
      // return alpha_prime;

    }
}
