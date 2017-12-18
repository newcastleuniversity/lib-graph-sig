package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Extended Euclidean Algorithm
 */
public class EEAlgorithm {

    private static final Logger log = Logger.getLogger(EEAlgorithm.class.getName());

    static private BigInteger r;
    static private BigInteger r_prime;
    static private BigInteger s = null;
    static private BigInteger s_prime;
    static private BigInteger t;
    static private BigInteger t_prime;
    static private BigInteger r_prime_prime;
    static private BigInteger q;

    public static BigInteger getS() {
        return s;
    }

    public static BigInteger getT() {
        return t;
    }

    public static BigInteger getD() {
        return d;
    }

    static private BigInteger d;


    private EEAlgorithm(final BigInteger d, final BigInteger s, final BigInteger t) {

        EEAlgorithm.d = d;
        EEAlgorithm.s = s;
        EEAlgorithm.t = t;
    }

    /**
     * Compute the Extended Euclidean Algorithm
     * based on <tt>alg:eea_schoup</tt> in topocert-doc
     *
     * @param a positive BigInteger > 0
     * @param b positive BigInteger > 0
     * @return d, s, t
     */
    public static EEAlgorithm computeEEAlgorithm(final BigInteger a, final BigInteger b) {

        if (a.compareTo(BigInteger.ZERO) <= 0)
            throw new IllegalArgumentException("EEA requires positive integers");

        if (b.compareTo(BigInteger.ZERO) <= 0)
            throw new IllegalArgumentException("EEA requires positive integers");

        BigInteger temps;
        BigInteger tempt;

        r = a;
        r_prime = b;
        s = BigInteger.ONE;
        temps = BigInteger.ZERO;
        tempt = BigInteger.ONE;
        s_prime = BigInteger.ZERO;
        t = BigInteger.ZERO;
        t_prime = BigInteger.ONE;


        while (r_prime.compareTo(BigInteger.ZERO) != 0) {

            q = r.divide(r_prime);
            r_prime_prime = r.mod(r_prime);

            r = r_prime;

            r_prime = r_prime_prime;

            temps = s_prime;
            tempt = t_prime;


            t_prime = t.subtract(t_prime.multiply(q));
            s_prime = s.subtract(s_prime.multiply(q));

            s = temps;
            t = tempt;

        }

        d = r;

        return  new EEAlgorithm(d, s, t);

    }
}
