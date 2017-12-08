package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Commitment Group value class
 */
public class CommitmentGroup {
    /** order of the subgroup of the commitment group /( \rho \)*/
    private BigInteger rho;
    /** commitment group modulus /( \Gamma \)*/
    private BigInteger gamma;
    private BigInteger g;
    private BigInteger r;
    private BigInteger h;
    private int l_rho;
    private int l_gamma;

    public CommitmentGroup(BigInteger rho, BigInteger gamma, BigInteger g, BigInteger h){


        this.rho = rho;
        this.gamma = gamma;
        this.g = g;
        this.h = h;
    }


    public BigInteger getRho() {
        return rho;
    }

    public BigInteger getGamma() {
        return gamma;
    }

    public BigInteger getG() {
        return g;
    }

    public BigInteger getH() {
        return h;
    }
}
