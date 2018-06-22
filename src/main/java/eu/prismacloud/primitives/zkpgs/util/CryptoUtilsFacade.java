package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.util.List;

/**
 * Wrapper Class for low-level number theoretic computations. Choose which implementation to use.
 */
public class CryptoUtilsFacade {
  private static final String GS = "GS";
  private static final String IDEMIX = "IDEMIX";

  private enum cryptoUtil {
    GS,
    IDEMIX
  };

  public CryptoUtilsFacade() {}

  public static BigInteger computeMultiBaseEx(
      List<BigInteger> bases, List<BigInteger> exponents, BigInteger N) {
    return CryptoUtilsFactory.getInstance(GS).multiBaseExp(bases, exponents, N);
  }

  public static BigInteger computePrimeWithLength(int minBitLength, int maxBitLength) {
    return CryptoUtilsFactory.getInstance(GS).generatePrimeWithLength(minBitLength, maxBitLength);
  }

  public static BigInteger computeRandomNumber(int bitLength) {
    return CryptoUtilsFactory.getInstance(GS).createRandomNumber(bitLength);
  }

  public static BigInteger computeHash(List<BigInteger> list, int hashLength) {

    return CryptoUtilsFactory.getInstance(GS).calculateHash(list, hashLength);
  }

  public static BigInteger computeA() {
    return CryptoUtilsFactory.getInstance(GS).computeA();
  }

  public SafePrime computeRandomSafePrime() {
    return CryptoUtilsFactory.getInstance(GS).generateRandomSafePrime();
  }

  public static SpecialRSAMod computeSpecialRSAModulus() {
    return CryptoUtilsFactory.getInstance(GS).generateSpecialRSAModulus();
  }

  public static BigInteger computeQRNGenerator(BigInteger n) {
    return CryptoUtilsFactory.getInstance(GS).createQRNGenerator(n);
  }

  public static BigInteger computeQRNElement(BigInteger n) {
    return CryptoUtilsFactory.getInstance(GS).createQRNElement(n);
  }

  public static BigInteger computeRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
    return CryptoUtilsFactory.getInstance(GS).createRandomNumber(lowerBound, upperBound);
  }

  public static CommitmentGroup commitmentGroupSetup() {
    return CryptoUtilsFactory.getInstance(IDEMIX).generateCommitmentGroup();
  }

  public static BigInteger commitmentGroupGenerator(BigInteger rho, BigInteger gamma) {
    return CryptoUtilsFactory.getInstance(GS).createCommitmentGroupGenerator(rho, gamma);
  }

  public static Boolean isElementOfQR(BigInteger value, BigInteger modulus) {
    return CryptoUtilsFactory.getInstance(GS).elementOfQRN(value, modulus);
  }

  public static BigInteger generateRandomPrime(int bitLength) {
    return CryptoUtilsFactory.getInstance(GS).generateRandomPrime(bitLength);
  }
}
