package uk.ac.ncl.cascade.zkpgs.util;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.CommitmentGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.Group;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SpecialRSAMod;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * Wrapper Class for low-level number theoretic computations. Choose which implementation to use.
 */
public class CryptoUtilsFacade {
  private static final String GS = "GS";
  
  @SuppressWarnings("unused")
private static final String IDEMIX = "IDEMIX";

  @SuppressWarnings("unused")
private enum cryptoUtil {
    GS,
    IDEMIX
  };

  public static BigInteger computeRandomNumberMinusPlus(int bitLength) {
    return CryptoUtilsFactory.getInstance(GS).randomMinusPlusNumber(bitLength);
  }

  public CryptoUtilsFacade() {}

  public static BigInteger computeMultiBaseExp(
      List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN) {
    return CryptoUtilsFactory.getInstance(GS).multiBaseExp(bases, exponents, modN);
  }

  public static BigInteger computeMultiBaseExpMap(
		  Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN) {
    return CryptoUtilsFactory.getInstance(GS).multiBaseExpMap(bases, exponents, modN);
  }
  
  public static GroupElement computeMultiBaseExp(
		  BaseCollection collection, BASE baseType, Group G) {
	  return CryptoUtilsFactory.getInstance(GS).computeMultiBaseExp(
			  collection, baseType, G);
  }
  
  public static GroupElement computeMultiBaseExp(
		  BaseCollection collection, Group G) {
	  return CryptoUtilsFactory.getInstance(GS).computeMultiBaseExp(
			  collection, G);
  }

  public static BigInteger computePrimeWithLength(int minBitLength, int maxBitLength) {
    return CryptoUtilsFactory.getInstance(GS).generatePrimeWithLength(minBitLength, maxBitLength);
  }

  public static BigInteger computePrimeInRange(BigInteger min, BigInteger max) {
    return CryptoUtilsFactory.getInstance(GS).generatePrimeInRange(min, max);
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

  public static SafePrime computeRandomSafePrime(KeyGenParameters keyGenParameters) {
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

  public static Boolean isPrime(BigInteger value){
    return CryptoUtilsFactory.getInstance(GS).isPrime(value);
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
  
  public static BigInteger getUpperPMBound(int bitLength) {
	  return CryptoUtilsFactory.getInstance(GS).getUpperPMBound(bitLength);
  }
  
  public static BigInteger getLowerPMBound(int bitLength) {
	  return CryptoUtilsFactory.getInstance(GS).getLowerPMBound(bitLength);
  }
  
  public static boolean isInPMRange(BigInteger number, int bitLength) {
	  return CryptoUtilsFactory.getInstance(GS).isInPMRange(number, bitLength);
  }

  public static boolean isInRange(BigInteger number, BigInteger min, BigInteger max) {
    return CryptoUtilsFactory.getInstance(GS).isInRange(number, min, max);
  }

  public static List<BigInteger> splitHexString(String str, int chunkLength){
    return CryptoUtilsFactory.getInstance(GS).splitHexString(str, chunkLength);
  }

  public static BigInteger joinHexString(List<BigInteger> splitArray){
    return CryptoUtilsFactory.getInstance(GS).joinHexString(splitArray);
  }
}
