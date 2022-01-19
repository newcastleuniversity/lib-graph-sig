package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.GSUtils;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SquareHashingTest {

	private static final GSUtils gsUtil = new GSUtils();
	private SpecialRSAMod safePrime;
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private SquareHashing squareHash;
	private BigInteger p;
	private BigInteger q;
	private BigInteger message;
	private BigInteger z;
	private BigInteger b;
	private BigInteger result;
	private static final int NUMBER_LENGTH = 512;
	private static final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
	private SpecialRSAMod rsaMod;

	@BeforeEach
	void setUp() {
		keyGenParameters = KeyGenParameters.createKeyGenParameters(NUMBER_LENGTH, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 0);
		rsaMod = gsUtil.generateSpecialRSAModulus();

		p = rsaMod.getP();
		q = rsaMod.getQ();
		log.info("safe prime p: " + p);
		log.info("safe prime p length: " + p.bitLength());
		log.info("safe prime q: " + q);
		log.info("safe prime q length: " + q.bitLength());
		assertTrue(gsUtil.isPrime(p));
		assertTrue(gsUtil.isPrime(q));

	}

	@AfterEach
	void tearDown() {
	}


	@Test
	void hash() {
		message = new BigInteger(N_G, 16);
		log.info("message: " + message);
		log.info("message length: " + message.bitLength());
		z = gsUtil.createRandomNumber(p.bitLength());
		log.info("z: " + z);
		log.info("z length: " + z.bitLength());

		b = gsUtil.createRandomNumber(p.bitLength());
		log.info("b: " + b);
		log.info("b length: " + b.bitLength());
		squareHash = new SquareHashing(p, z, b);
		assertNotNull(squareHash);
		result = squareHash.hash(message);
		assertNotNull(result);
		log.info("result: " + result);
		log.info("result length: " + result.bitLength());
	}
}