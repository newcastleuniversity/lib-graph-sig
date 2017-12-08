package eu.prismacloud.primitives.grs.utils;

import com.ibm.zurich.idmx.utils.Utils;
import eu.prismacloud.primitives.grs.parameters.KeyGenParameters;

import java.math.BigInteger;
import java.util.logging.Logger;

/**
 * Wrapper for generating safe primes
 */
public class SafePrime {

    private BigInteger a;
    SafePrime sf;
    BigInteger a_prime;

    private static final Logger log = Logger.getLogger(SafePrime.class.getName());

    /**
     * Instantiates a new Safe prime p with its corresponding Sophie Germain prime p'.
     * \( p = 2p' + 1 \)
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
//        a_prime =  a.asubtract(ONE).shiftRight(1);
        return new SafePrime(sf.a, sf.a_prime);
    }





}
