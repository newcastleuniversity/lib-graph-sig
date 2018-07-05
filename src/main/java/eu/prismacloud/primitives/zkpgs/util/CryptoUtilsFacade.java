package eu.prismacloud.primitives.zkpgs.util;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

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

  public static BigInteger computeRandomNumberMinusPlus(int bitLength) {
    return CryptoUtilsFactory.getInstance(GS).randomMinusPlusNumber(bitLength);
  }

  public CryptoUtilsFacade() {}

  public static BigInteger computeMultiBaseEx(
      List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN) {
    return CryptoUtilsFactory.getInstance(GS).multiBaseExp(bases, exponents, modN);
  }

  public static BigInteger computeMultiBaseExMap(
      Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
    return CryptoUtilsFactory.getInstance(GS).multiBaseExpMap(bases, exponents, modN);
  }

  public static BigInteger computePrimeWithLength(int minBitLength, int maxBitLength) {
    return CryptoUtilsFactory.getInstance(GS).generatePrimeWithLength(minBitLength, maxBitLength);
  }

  public static BigInteger computeRandomNumber(int bitLength) {
    return CryptoUtilsFactory.getInstance(GS).createRandomNumber(bitLength);
  }

  public static BigInteger computeHash(List<String> list, int hashLength)
      throws NoSuchAlgorithmException {
    return CryptoUtilsFactory.getInstance(GS).computeHash(list, hashLength);
  }

  public static GSSignature generateSignature(
      final BigInteger m, final BaseRepresentation base, final SignerPublicKey signerPublicKey) {
    return CryptoUtilsFactory.getInstance(GS).generateSignature(m, base, signerPublicKey);
  }

  public static BigInteger computeA() {
    return CryptoUtilsFactory.getInstance(GS).computeA();
  }

  public SafePrime computeRandomSafePrime(KeyGenParameters keyGenParameters) {
    return CryptoUtilsFactory.getInstance(GS).generateRandomSafePrime(keyGenParameters);
  }

  public static SpecialRSAMod computeSpecialRSAModulus(KeyGenParameters keyGenParameters) {
    return CryptoUtilsFactory.getInstance(GS).generateSpecialRSAModulus();
  }

//  public static QRElement computeQRNGenerator(BigInteger n) {
//    return CryptoUtilsFactory.getInstance(GS).createQRNGenerator(n);
//  }

//  public static QRElement computeQRNElement(BigInteger n) {
//    return CryptoUtilsFactory.getInstance(GS).createQRNElement(n);
//  }

  public static BigInteger computeRandomNumber(BigInteger lowerBound, BigInteger upperBound) {
    return CryptoUtilsFactory.getInstance(GS).createRandomNumber(lowerBound, upperBound);
  }

  public static CommitmentGroup commitmentGroupSetup(
      KeyGenParameters keyGenParameters) {
    return CryptoUtilsFactory.getInstance(GS).generateCommitmentGroup();
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
  
  public static BigInteger createElementOfZNS(final BigInteger modN) {
	  return CryptoUtilsFactory.getInstance(GS).createElementOfZNS(modN);
  }
  
  public static boolean verifySGeneratorOfQRN(BigInteger s, BigInteger modN) {
	  return CryptoUtilsFactory.getInstance(GS).verifySGeneratorOfQRN(s, modN);
  }
}
