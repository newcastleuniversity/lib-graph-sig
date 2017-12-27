package eu.prismacloud.primitives.grs.utils;

import java.math.BigInteger;

/**
 * Interface for Number Theoretic utilities
 */
public interface INumberUtils {

    SafePrime generateRandomSafePrime();

    SpecialRSAMod generateSpecialRSAModulus();

    BigInteger createQRNGenerator(BigInteger n);

    BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound);

    CommitmentGroup generateCommitmentGroup();

    BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma);

    Boolean elementOfQR(BigInteger value, BigInteger modulus);
}
