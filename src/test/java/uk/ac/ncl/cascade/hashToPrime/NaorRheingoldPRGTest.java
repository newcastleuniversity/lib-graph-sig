package uk.ac.ncl.cascade.hashToPrime;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.PrimeOrderGroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SafePrime;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertTrue;

class NaorRheingoldPRGTest {
	private static final int MODULUS_LENGTH = 512;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private static KeyGenParameters keyGenParameters;
	private static FilePersistenceUtil persistenceUtil;
	private static Boolean isFile = false;
	private static PrimeOrderGroup group;
	private static SafePrime safePrime;
	private static GroupElement generator;

	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		persistenceUtil = new FilePersistenceUtil();
		keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);
		File f = new File(GROUP_FILENAME);
		isFile = f.exists();
		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {
			safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);

			log.info("safeprime : " + safePrime.getSafePrime());
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
			generator = group.createGenerator();
			persistenceUtil.write(group, GROUP_FILENAME);
		}
	}

	@AfterEach
	void tearDown() {
	}

	@Test
	void compute() {
		PrimeOrderGroupElement el = (PrimeOrderGroupElement) group.createRandomElement();
		PrimeOrderGroupElement x = (PrimeOrderGroupElement) group.createRandomElement();
		log.info("x:" + x);
		NaorRheingoldPRG nr = new NaorRheingoldPRG(group);
		BigInteger res;

		do {
			res = nr.compute(x.getValue());
		} while (!res.isProbablePrime(keyGenParameters.getL_pt()));

		assertTrue(((PrimeOrderGroup) group).isElement(res));
		assertTrue(res.isProbablePrime(keyGenParameters.getL_pt()));
		log.info("res: " + res);
		log.info("bitlength: " + res.bitLength());
	}

}