package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.util.List;

/** Interface for Number Theoretic utilities */
public interface INumberUtils {

  SafePrime generateRandomSafePrime();

  SpecialRSAMod generateSpecialRSAModulus();

  BigInteger createQRNGenerator(BigInteger N);

  BigInteger createRandomNumber(BigInteger min, BigInteger max);

  BigInteger createRandomNumber(int bitLength);

  CommitmentGroup generateCommitmentGroup();

  BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma);

  Boolean elementOfQRN(BigInteger value, BigInteger modulus);

  BigInteger createQRNElement(BigInteger N);

  BigInteger calculateHash(List<BigInteger> list, int hashLength);

  BigInteger computeA();

  BigInteger generateRandomPrime(int bitLength);

  BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents, BigInteger N);

  BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength);
}
