package uk.ac.ncl.cascade.util.crypto;

import org.junit.jupiter.api.Disabled;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroup;
import uk.ac.ncl.cascade.zkpgs.util.crypto.PrimeOrderGroupElement;
import uk.ac.ncl.cascade.zkpgs.util.crypto.SafePrime;

import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Created by Ioannis Sfyrakis on 17/01/2022
 */
@Disabled
class PrimeOrderGroupTest {

	private static final int MODULUS_LENGTH = 1632;
	private static Logger log = GSLoggerConfiguration.getGSlog();
	private static PrimeOrderGroup group;
	private static PrimeOrderGroupElement g;
	private static KeyGenParameters keyGenParameters;
	private static SafePrime safePrime;
	private static final String GROUP_FILENAME = "prime_order_group.ser";
	private static Boolean isFile = false;
	private static FilePersistenceUtil persistenceUtil;
		
	@BeforeAll
	static void setUp() throws IOException, ClassNotFoundException {
		persistenceUtil = new FilePersistenceUtil();

		File f = new File(GROUP_FILENAME);
		isFile = f.exists();

		if (isFile) {
			group = (PrimeOrderGroup) persistenceUtil.read(GROUP_FILENAME);
		} else {

			keyGenParameters = KeyGenParameters.createKeyGenParameters(MODULUS_LENGTH, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);
			safePrime = CryptoUtilsFacade.computeRandomSafePrime(keyGenParameters);

			log.info("safeprime : " + safePrime.getSafePrime());
			group = new PrimeOrderGroup(safePrime.getSafePrime(), safePrime.getSophieGermain());
		}
	}

	@AfterEach
	void tearDown() {
	}

	@Test
	void createGeneratorSubGroup() throws IOException {

		if (isFile) {
			GroupElement generator = group.getGenerator();
			log.info("generator: " + generator);
			assertNotNull(generator);
			assertTrue(group.isElement(group.getGenerator().getValue()));
			GroupElement el = group.createRandomElement();
			assertTrue(group.isElement(el.getValue()));
			log.info("element: " + el);
		} else {
			GroupElement generator = group.createGenerator();
			log.info("generator: " + generator);
			assertNotNull(generator);
			assertTrue(group.isElement(group.getGenerator().getValue()));
			GroupElement el = group.createRandomElement();
			assertTrue(group.isElement(el.getValue()));
			log.info("element: " + el);
			persistenceUtil.write(group, "prime_order_group.ser");
		}


//		persistenceUtil.write(group, "prime_order_group.ser");
//		persistenceUtil.write(generator, "generator.ser");
//		persistenceUtil.write(el, "group_element.ser");


	}
}