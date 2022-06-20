package uk.ac.ncl.cascade.zkpgs.util;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.crypto.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;

/**
 * Interface for Number Theoretic utilities
 */
public interface INumberUtils {

	SafePrime generateRandomSafePrime(
			KeyGenParameters keyGenParameters);

	SpecialRSAMod generateSpecialRSAModulus();

	// QRElement createQRNGenerator(BigInteger N);

	BigInteger createRandomNumber(BigInteger min, BigInteger max);

	BigInteger createRandomNumber(int bitLength);

	CommitmentGroup generateCommitmentGroup();

	BigInteger createCommitmentGroupGenerator(BigInteger rho, BigInteger gamma);

	Boolean elementOfQRN(BigInteger value, BigInteger modulus);

//  QRElement createQRNElement(BigInteger N);

	BigInteger computeHash(List<String> list, int hashLength) throws NoSuchAlgorithmException;

	BigInteger computeA();

	BigInteger generateRandomPrime(int bitLength);

	BigInteger multiBaseExp(List<BigInteger> bases, List<BigInteger> exponents, BigInteger modN);

	BigInteger multiBaseExpMap(Map<URN, GroupElement> bases, Map<URN, BigInteger> exponents, BigInteger modN);

	GroupElement computeMultiBaseExp(
			BaseCollection collection, BASE baseType, Group G);

	GroupElement computeMultiBaseExp(
			BaseCollection collection, Group G);

	BigInteger generatePrimeWithLength(int minBitLength, int maxBitLength);

	BigInteger randomMinusPlusNumber(int bitLength);

	GSSignature generateSignature(BigInteger m, BaseRepresentation base,
								  SignerPublicKey signerPublicKey);

	BigInteger createElementOfZNS(BigInteger modN);

	boolean verifySGeneratorOfQRN(BigInteger s, BigInteger modN);

	BigInteger generatePrimeInRange(BigInteger min, BigInteger max);

	BigInteger getUpperPMBound(int bitLength);

	BigInteger getLowerPMBound(int bitLength);

	boolean isInPMRange(BigInteger number, int bitLength);

	boolean isInRange(BigInteger number, BigInteger min, BigInteger max);

	Boolean isPrime(BigInteger value);

	List<BigInteger> splitHexString(String str, int chunkLength);

	BigInteger joinHexString(List<BigInteger> splitArray);
}
