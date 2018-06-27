package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

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

  BigInteger computeHash(List<String> list, int hashLength) throws NoSuchAlgorithmException;

  BigInteger computeA();

  BigInteger generateRandomPrime(int bitLength);

  BigInteger multiBaseExp(Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN);

  BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength);

  BigInteger randomMinusPlusNumber(int bitLength);

  GSSignature generateSignature(BigInteger m, BaseRepresentation base,
      SignerPublicKey signerPublicKey);
}
