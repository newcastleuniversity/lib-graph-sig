package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Special RSA Modulus class
 */
public class SpecialRSAMod {

    private final BigInteger n;
    private BigInteger p;
    private BigInteger q;
    private BigInteger p_prime;
    private BigInteger q_prime;
    private SafePrime sp;
    private SafePrime sq;

    public SpecialRSAMod(BigInteger N, BigInteger p, BigInteger q, BigInteger p_prime, BigInteger q_prime){

        n = N;
        this.p = p;
        this.q = q;
        this.p_prime = p_prime;
        this.q_prime = q_prime;
    }

    public SpecialRSAMod(BigInteger n, SafePrime sp, SafePrime sq) {
        this.n = n;
        this.sp = sp;
        this.sq = sq;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getP() {
        return sp.getSafePrime();
    }

    public BigInteger getQ() {
        return sq.getSafePrime();
    }

    public BigInteger getP_prime() {
        return sp.getSophieGermain();
    }

    public BigInteger getQ_prime() {
        return sq.getSophieGermain();
    }

//    public SpecialRSAMod generateSpecialRSAModulus(){
//        CryptoUtilsFacade cf = new CryptoUtilsFacade();
//        cf
//        return new SpecialRSAMod(new BigInteger("1"), new BigInteger("2"), new BigInteger("2"), new BigInteger("3"),new BigInteger("5") );
//    }
}
