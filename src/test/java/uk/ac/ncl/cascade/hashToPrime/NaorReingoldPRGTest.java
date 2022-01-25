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
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

class NaorReingoldPRGTest {
	private static final int MODULUS_LENGTH = 256;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private static KeyGenParameters keyGenParameters;
	private static PrimeOrderGroup group;
	private static final String xst = "4408805283949452337274944115912404368023120815201040683313987545615992267988276742708053935754414213038144405485965997490557246410588106909994721006983224";

	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);
		File f = new File(GROUP_FILENAME);
		boolean isFile = f.exists();
		log.info("group file exists: " + isFile);
		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {
			SafePrime safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);

			log.info("safeprime : " + safePrime.getSafePrime());
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			GroupElement generator = group.createGenerator();
			persistenceUtil.write(group, GROUP_FILENAME);
		}
	}

	@Test
	@DisplayName("computes the output prime from the NR generator using fixed big integer as input")
	void computeWithKnownx() {

		BigInteger x = new BigInteger(xst, 10);
		log.info("x:" + x);
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		BigInteger res;
		List<BigInteger> sequence;
		do {
			sequence = nr.computeVectorA(x.bitLength() + 1);
			res = nr.compute(x, sequence);
		} while (!res.isProbablePrime(keyGenParameters.getL_pt()));

		assertTrue(group.isElement(res));
		assertTrue(res.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("res: " + res);
		log.info("bitlength: " + res.bitLength());
	}

	@Test
	@DisplayName("computes the output prime from the NR generator using a random x big integer as input")
	void compute() {

		BigInteger x = CryptoUtilsFacade.computeRandomNumber(512);
		log.info("x:" + x);
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		BigInteger res;
		List<BigInteger> sequence;
		do {
			sequence = nr.computeVectorA(x.bitLength() + 1);
			res = nr.compute(x, sequence);
		} while (!res.isProbablePrime(keyGenParameters.getL_pt()));

		assertTrue(group.isElement(res));
		assertTrue(res.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("res: " + res);
		log.info("bitlength: " + res.bitLength());
	}

	@Test
	@DisplayName("recompute prime with saved random sequence")
	void recomputePrime() {
		BigInteger x = CryptoUtilsFacade.computeRandomNumber(512);
		log.info("x:" + x);
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		BigInteger res;
		List<BigInteger> sequence;
		do {
			sequence = nr.computeVectorA(x.bitLength() + 1);
			res = nr.compute(x, sequence);
		} while (!res.isProbablePrime(keyGenParameters.getL_pt()));

		assertTrue(group.isElement(res));
		assertTrue(res.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("res: " + res);
		log.info("bitlength: " + res.bitLength());

		NaorReingoldPRG nrprg = new NaorReingoldPRG(group);

		BigInteger pr = nrprg.compute(x, sequence);
		assertTrue(pr.isProbablePrime(keyGenParameters.getL_pt()));
		assertEquals(pr, res);

	}


	@Test
	@DisplayName("check if the NR generator outputs the same prime")
	void checkIfNROutputSamePrime() {
//		assumeTrue(BaseTest.EXECUTE_INTENSIVE_TESTS);
		List<BigInteger> primes = new ArrayList<BigInteger>();
		BigInteger x = CryptoUtilsFacade.computeRandomNumber(128);
		log.info("x:" + x);
		for (int i = 0; i < 10000; i++) {

			NaorReingoldPRG nr = new NaorReingoldPRG(group);
			BigInteger res;
			List<BigInteger> sequence;
			do {
				sequence = nr.computeVectorA(x.bitLength() + 1);
				res = nr.compute(x, sequence);
			} while (!res.isProbablePrime(keyGenParameters.getL_pt()));

			assertTrue(group.isElement(res));
			assertTrue(res.isProbablePrime(keyGenParameters.getL_pt()));
			log.info("index: " + i + " prime: " + res);
			log.info("prime bitlength: " + res.bitLength());
			if (i == 0) {
				primes.add(i, res);
			} else {
				assertFalse(primes.contains(res));
				primes.add(i, res);
			}
			log.info("list size: " + primes.size());
		}

	}

	@Test
	@DisplayName("check the size of the list and the each element bitlength")
	void computeVectorA() {
		int size = 10;
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		List<BigInteger> list = nr.computeVectorA(size);
		assertEquals(size, list.size());
		for (int i = 0; i < size; i++) {
			BigInteger el = list.get(i);
			assertNotNull(el);
			assertTrue(el.bitLength() <= group.getOrder().bitLength());
		}
	}

	@Test
	@DisplayName("check if the bitstring returned is the correct binary representation of the biginteger")
	void convertToBitString() {
		BigInteger number = CryptoUtilsFacade.computeRandomNumber(512);
		String bitstring = number.toString(2);
		NaorReingoldPRG nr = new NaorReingoldPRG(group);
		String nrbits = nr.convertToBitString(number);
		assertEquals(bitstring, nrbits);
	}
}