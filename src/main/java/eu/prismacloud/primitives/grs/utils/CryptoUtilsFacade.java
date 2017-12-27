package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Wrapper Class for low-level number theoretic computations. Choose which implementation to use.
 */
public class CryptoUtilsFacade {


    protected CryptoUtilsFacade() {
    }

    public SafePrime computeRandomSafePrime() {
        return CryptoUtilsFactory.getInstance("GS").generateRandomSafePrime();
    }


    public static SpecialRSAMod computeSpecialRSAModulus() {
        return CryptoUtilsFactory.getInstance("GS").generateSpecialRSAModulus();
    }

    public static BigInteger computeQRNGenerator(BigInteger n) {
        return CryptoUtilsFactory.getInstance("GS").createQRNGenerator(n);
    }

    public static BigInteger computeRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
        return CryptoUtilsFactory.getInstance("GS").createRandomNumber(lowerBound, upperBound);
    }

    public static CommitmentGroup commitmentGroupSetup() {
        return CryptoUtilsFactory.getInstance("GS").generateCommitmentGroup();
    }

    public static BigInteger commitmentGroupGenerator(BigInteger rho, BigInteger gamma) {
        return CryptoUtilsFactory.getInstance("GS").createCommitmentGroupGenerator(rho, gamma);
    }

    public static Boolean isElementOfQR(BigInteger value, BigInteger modulus) {
        return CryptoUtilsFactory.getInstance("GS").elementOfQR(value, modulus);
    }
}
