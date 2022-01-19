package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HashToPrimeEliminationTest {
	private static final int MODULUS_LENGTH = 512;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private static KeyGenParameters keyGenParameters;
	private static FilePersistenceUtil persistenceUtil;
	private static Boolean isFile = false;
	private static PrimeOrderGroup group;
	private static SafePrime safePrime;
	private static GroupElement generator;
	private static final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";

	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);

		persistenceUtil = new FilePersistenceUtil();

		File f = new File(GROUP_FILENAME);
		isFile = f.exists();
		
		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {

			safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			generator = group.createGenerator();
			persistenceUtil.write(group,GROUP_FILENAME);
		}
	}

	@Test
	void computeSquareHashWithNG() {
		HashToPrimeElimination htp = new HashToPrimeElimination(group, keyGenParameters);
		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);
		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());

	}

	@Test
	void computeSquareHash() {
		HashToPrimeElimination htp = new HashToPrimeElimination(group, keyGenParameters);
		BigInteger message = CryptoUtilsFacade.computeRandomNumber(1632);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);
		log.info("result: " + res);
		log.info("result bitlength: " + res.bitLength());

	}

	@Test
	void computePrime() {
		HashToPrimeElimination htp = new HashToPrimeElimination(group, keyGenParameters);
		BigInteger message = new BigInteger(N_G, 16);

		BigInteger res = htp.computeSquareHash(message);
		assertNotNull(res);

		BigInteger prime = htp.computePrime(res);
		assertNotNull(prime);
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("prime: " + prime);
		log.info("prime bitlength: " + prime.bitLength());

	}

	@Test
	void getCandidates() {
		HashToPrimeElimination htp = new HashToPrimeElimination(group, keyGenParameters);
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

	@Test
	void primalityZKProof() {
		// TODO implement tests for primality zk proof when hashing to prime by elimination
	}
}