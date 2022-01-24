package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class HashToPrimeEliminationTest {
	private static final int MODULUS_LENGTH = 512;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private static KeyGenParameters keyGenParameters;
	private static PrimeOrderGroup group;
	private static final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
	private BigInteger message;

	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);

		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();

		File f = new File(GROUP_FILENAME);
		boolean isFile = f.exists();

		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {

			SafePrime safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			GroupElement generator = group.createGenerator();
			persistenceUtil.write(group, GROUP_FILENAME);
		}
	}

	@Test
	@DisplayName("test computing square hash with a fixed NG input")
	void computeSquareHashWithNG() {
		log.info("setup square hashing");
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());

		SquareHashing sq = new SquareHashing(sqPrime, z, b);
		BigInteger hs = sq.hash(message);
		assertEquals(hs, res);
	}

	@Test
	@DisplayName("test computing square hash with a random message")
	void computeSquareHash() {
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = CryptoUtilsFacade.computeRandomNumber(1632);
		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);
		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());
		SquareHashing sq = new SquareHashing(sqPrime, z, b);
		BigInteger hs = sq.hash(message);
		assertEquals(hs, res);
	}

	@Test
	@DisplayName("test computing a prime with a fixed input message")
	void computePrimeNG() {
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		BigInteger prime = htp.computePrime(res);
		assertNotNull(prime);
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("prime: " + prime);
		log.info("prime bitlength: " + prime.bitLength());
		NaorReingoldPRG nrprg = new NaorReingoldPRG(group);
		BigInteger htPrime;
		List<BigInteger> primeSequence;

		primeSequence = htp.getPrimeSequence();
		htPrime = nrprg.compute(res,primeSequence);
		
		assertTrue(htPrime.isProbablePrime(keyGenParameters.getL_pt()));
		assertEquals(htPrime, prime);
	}

	@Test
	@DisplayName("test returning candidates after finding a prime number")
	void getCandidates() {

		log.info("setup square hashing");
		SafePrime sqSafePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
		BigInteger sqPrime = sqSafePrime.getSafePrime();
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		BigInteger z = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		BigInteger b = CryptoUtilsFacade.computeRandomNumber(sqPrime.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		SquareHashing squareHash = new SquareHashing(sqPrime, z, b);
		log.info("setup NRPRG");
		NaorReingoldPRG nr = new NaorReingoldPRG(group);

		HashToPrimeElimination htp = new HashToPrimeElimination(squareHash, nr, keyGenParameters);

		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		BigInteger prime = htp.computePrime(res);
		assertNotNull(prime);
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));

		List<BigInteger> cand = htp.getCandidates();
		assertNotNull(cand);
		assertTrue(cand.size() > 0);
		log.info("size of candidates: " + cand.size());
	}
	
}