package eu.prismacloud.primitives.grs.util;

import eu.prismacloud.primitives.grs.util.crypto.SpecialRSAMod;
import eu.prismacloud.primitives.grs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.grs.util.crypto.SafePrime;
import java.math.BigInteger;

/** Interface for Number Theoretic utilities */
public interface INumberUtils {

  SafePrime generateRandomSafePrime();

  SpecialRSAMod generateSpecialRSAModulus();

  BigInteger createQRNGenerator(BigInteger n);

  BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound);

  CommitmentGroup generateCommitmentGroup();

  BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma);

  Boolean elementOfQRN(BigInteger value, BigInteger modulus);

  BigInteger createQRNElement(BigInteger n);
}
