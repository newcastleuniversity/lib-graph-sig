package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Wrapper for generating safe primes
 */
public class SafePrime {

    private BigInteger a;
    private SafePrime sf;
    private BigInteger a_prime;

    private static final Logger log = Logger.getLogger(SafePrime.class.getName());

    /**
     * Instantiates a new Safe prime p with its corresponding Sophie Germain prime p'.
     * \( p = 2p' + 1 \)
     *
     * @param safePrime     the safe prime
     * @param sophieGermain the Sophie Germain prime
     */
    public SafePrime(final BigInteger safePrime, final BigInteger sophieGermain) {
        this.a = safePrime;
        this.a_prime = sophieGermain;
    }

    protected SafePrime() {

    }

    public BigInteger getSafePrime() {
        return a;
    }

    public BigInteger getSophieGermain() {
        return a_prime;
    }

    /**
     * Generate random safe prime safe prime.
     *
     * @return the safe prime
     */
    public SafePrime generateRandomSafePrime() {
        CryptoUtilsFacade cuf = new CryptoUtilsFacade();
        sf = cuf.computeRandomSafePrime();
        return new SafePrime(sf.a, sf.a_prime);
    }

}
