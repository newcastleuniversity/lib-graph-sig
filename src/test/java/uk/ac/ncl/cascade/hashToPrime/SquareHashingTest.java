package uk.ac.ncl.cascade.hashToPrime;

import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SpecialRSAMod;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class SquareHashingTest {
	private SpecialRSAMod safePrime;
	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private BigInteger p;
	private static final int NUMBER_LENGTH = 512;
	private static final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
	private SpecialRSAMod rsaMod;

	@BeforeEach
	void setUp() {
		KeyGenParameters keyGenParameters = KeyGenParameters.createKeyGenParameters(NUMBER_LENGTH, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0);
		SafePrime safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);

		p = safePrime.getSafePrime();
		BigInteger q = safePrime.getSophieGermain();
		log.info("safe prime p: " + p);
		log.info("safe prime p length: " + p.bitLength());
		log.info("safe prime q: " + q);
		log.info("safe prime q length: " + q.bitLength());
		assertTrue(CryptoUtilsFacade.isPrime(p));
		assertTrue(CryptoUtilsFacade.isPrime(q));

	}

	@Test
	@DisplayName("Test square hash method with a fixed NG value")
	void hashNG() {
		BigInteger message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z =  CryptoUtilsFacade.computeRandomNumber(p.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b =  CryptoUtilsFacade.computeRandomNumber(p.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(p, z, b);
		assertNotNull(squareHash);
		BigInteger result = squareHash.hash(message);
		assertNotNull(result);
		squareHash = new SquareHashing(p, z, b);
		assertEquals(squareHash.hash(message), result);
		log.info("result: " + result);
		log.info("result length: " + result.bitLength());
		log.info("square hash: " + squareHash.hash(message));
	}
	@Test
	@DisplayName("Test square hash method with a random input value")
	void hash() {
		BigInteger message = CryptoUtilsFacade.computeRandomNumber(1632);

		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(p.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());
		BigInteger b = CryptoUtilsFacade.computeRandomNumber(p.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(p, z, b);
		assertNotNull(squareHash);
		BigInteger result = squareHash.hash(message);
		assertNotNull(result);
		squareHash = new SquareHashing(p, z, b);
		assertEquals(squareHash.hash(message), result);
		log.info("result: " + result);
		log.info("result length: " + result.bitLength());
		log.info("square hash: " + squareHash.hash(message));
	}

}