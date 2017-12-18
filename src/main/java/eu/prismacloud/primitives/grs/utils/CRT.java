package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Chinese Remainder Theorem
 */
public class CRT {

    private static final Logger log = Logger.getLogger(CRT.class.getName());
    private static BigInteger v;
    private static BigInteger x;
    private static BigInteger c2;

    /**
     * Nested Class for holding pq representation.
     */
    public static class PQRepresentation {
        private final BigInteger xp;
        private final BigInteger xq;

        public BigInteger getXp() {
            return xp;
        }

        public BigInteger getXq() {
            return xq;
        }

        private PQRepresentation(final BigInteger xp, final BigInteger xq) {

            this.xp = xp;
            this.xq = xq;
        }
    }

    /**
     * Compute Chinese Remainder Theorem to solve congruencies
     * (\ x \equiv a mod p \)
     * (\ x \equiv b mod q \)
     *
     * @param a positive integer number > 0
     * @param p prime factor of N
     * @param b positive integer number > 0
     * @param q prime factor of N
     * @return x solution of congruences
     */
    public static BigInteger computeCRT(final BigInteger a, final BigInteger p, final BigInteger b, final BigInteger q) {

        if (p.equals(q))
            throw new IllegalArgumentException("factors must be different");

        if (p.gcd(q).compareTo(BigInteger.ONE) != 0)
            throw new IllegalArgumentException("factors are not coprime");

        EEAlgorithm.computeEEAlgorithm(p, q);

        c2 = EEAlgorithm.getS();

        v = c2;

        v = (b.subtract(a).multiply(c2.mod(q)));
        x = a.add(v.multiply(p));

        return x;

    }

    /**
     * Convert an element represented as (xp, xq) to its representation modulo N
     * knowing the factors p an q
     *
     * @param xp element in modulo p representation
     * @param p  prime factor
     * @param xq element in modulo q representation
     * @param q  prime factor
     * @return element in modulo N representation
     */
    public static BigInteger convertToModuloN(BigInteger xp, BigInteger p, BigInteger xq, BigInteger q) {

        BigInteger N = p.multiply(q);
        EEAlgorithm.computeEEAlgorithm(p, q);
        BigInteger x = EEAlgorithm.getS();
        BigInteger y = EEAlgorithm.getT();

        BigInteger onep = y.multiply(q).mod(N);
        BigInteger oneq = x.multiply(p).mod(N);

        return xp.multiply(onep).add(xq.multiply(oneq)).mod(N);

    }

    /**
     * Convert an element x modulo N to its corresponding representation
     * modulo p and modulo q.
     *
     * @param x element x in modulo N representation
     * @param p prime factor of N
     * @param q prime factor of N
     * @return modulo p and modulo q representation (\ (x mod p) , (x mod q) \)
     */
    public static PQRepresentation convertToPQ(BigInteger x, BigInteger p, BigInteger q) {


        return new PQRepresentation(x.mod(p), x.mod(q));
    }


}
