package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.util.Vector;

/** Interface for Number Theoretic utilities */
public interface INumberUtils {

  SafePrime generateRandomSafePrime();

  SpecialRSAMod generateSpecialRSAModulus();

  BigInteger createQRNGenerator(BigInteger n);

  BigInteger createRandomNumber(BigInteger lowerBound, BigInteger upperBound);

  BigInteger createRandomNumber(int bitLength);

  CommitmentGroup generateCommitmentGroup();

  BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma);

  Boolean elementOfQRN(BigInteger value, BigInteger modulus);

  BigInteger createQRNElement(BigInteger n);

  BigInteger calculateHash(Vector<BigInteger> list, int hashLength);
}
