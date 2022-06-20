package uk.ac.ncl.cascade.util;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.parameters.JSONParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import org.junit.jupiter.api.*;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.GSUtils;
import uk.ac.ncl.cascade.zkpgs.util.NumberConstants;
import uk.ac.ncl.cascade.zkpgs.util.crypto.*;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Test GSUtils class
 */
class GSUtilsTest {

	private static final Logger log = GSLoggerConfiguration.getGSlog();
	private KeyGenParameters keyGenParameters;
	private GSUtils classUnderTest;

	private SpecialRSAMod specialRSAModMock;

	private GSUtils gsUtilsMock;

	@BeforeEach
	void setUp() {
		JSONParameters parameters = new JSONParameters();
		keyGenParameters = parameters.getKeyGenParameters();
		classUnderTest = new GSUtils();
	}

	@Test
	@DisplayName("Test generate Special RSA modulus")
	void generateSpecialRSAModulus() {
		assumeTrue(BaseTest.EXECUTE_INTENSIVE_TESTS);

		log.info("@Test: generateSpecialRSAModulus");
		SpecialRSAMod srm = classUnderTest.generateSpecialRSAModulus();
		assertNotNull(srm);
		assertEquals(srm.getN(), srm.getP().multiply(srm.getQ()));
	}

	@Test
	@DisplayName("Test generate Special RSA modulus for uniqueness")
	void generateUniqueSpecialRSAModulus() {
		assumeTrue(BaseTest.EXECUTE_INTENSIVE_TESTS);

		log.info("@Test: generateSpecialRSAModulus");
		int arraySize = 10;
		SpecialRSAMod[] srmArray = new SpecialRSAMod[arraySize];

		for (int i = 0; i < arraySize; i++) {
			SpecialRSAMod srm = classUnderTest.generateSpecialRSAModulus();
			assertNotNull(srm);
			assertEquals(srm.getN(), srm.getP().multiply(srm.getQ()));
			srmArray[i] = srm;
		}

		for (int i = 0; i < arraySize; i++) {
			SpecialRSAMod isrm = srmArray[i];
			for (int j = 0; j < arraySize; j++) {
				if (i != j) {
					SpecialRSAMod jSrm = srmArray[j];
					if (isrm.equals(jSrm)) {
						fail("Duplicate modulus modN generated");
					}
				}
			}
		}
	}

	@Test
	@Disabled("generate commitment group")
	@DisplayName("Test generate commitment group")
	void generateCommitmentGroup() {
		log.info("@Test: generate commitment group");
		assertNotNull(classUnderTest);
		CommitmentGroup cg = classUnderTest.generateCommitmentGroup();
		assertNotNull(cg);
		log.info("rho: " + cg.getRho());
		log.info("gamma: " + cg.getGamma());
		log.info("g: " + cg.getG());
		log.info("h:" + cg.getH());
	}

	@Test
	@DisplayName("Test generate Prime")
	void generatePrime() {
		log.info("@Test: generateRandomPrime ");
		GSUtils gs = new GSUtils();
		BigInteger bg = gs.generateRandomPrime(keyGenParameters.getL_n() / 2);
		log.info("bg: " + bg);
		assertNotNull(bg);
		assertTrue(bg.isProbablePrime(80));
	}

	@Test
	@Disabled("testing commmitment group generator")
	@DisplayName("create commitment group generator")
	void createCommitmentGroupGenerator() {
		log.info("@Test: createCommitmentGroupGenerator");
		BigInteger gamma, g;
		BigInteger m = BigInteger.probablePrime(keyGenParameters.getL_gamma(), new SecureRandom());
		gamma = classUnderTest.computeCommitmentGroupModulus(m);
		log.info("gamma: " + gamma);
		log.info("gamma bitlength: " + gamma.bitLength());
		assertNotNull(gamma);

		g = classUnderTest.createCommitmentGroupGenerator(classUnderTest.getRho(), gamma);

		assertNotNull(g);
		// g^rho mod gamma = 1 mod gamma
		assertEquals(
				g.modPow(classUnderTest.getRho(), gamma.add(BigInteger.ONE)),
				BigInteger.ONE.mod(gamma.add(BigInteger.ONE)));
	}

	@Test
	@Disabled("testing commitment group modulus")
	@DisplayName("compute commitment group modulus")
	void computeCommitmentGroupModulus() {
		log.info("@Test: computeCommitmentGroupModulus");
		BigInteger mingamma, res;
		BigInteger m = BigInteger.probablePrime(keyGenParameters.getL_gamma(), new SecureRandom());
		//        BigInteger rho = BigInteger.probablePrime(16,new SecureRandom());

		mingamma = classUnderTest.computeCommitmentGroupModulus(m);
		log.info("gamma: " + mingamma);
		log.info("gamma bitlength: " + mingamma.bitLength());
		assertNotNull(mingamma);
		// check rho divides gamma - 1 = mingamma
		res = mingamma.divideAndRemainder(classUnderTest.getRho())[1];
		log.info("divides: " + res);
		assertEquals(BigInteger.ZERO, res);
	}

	@Test
	@DisplayName("generate random number in range")
	void createRandomNumber() {
		log.info("@Test: createRandomNumber ");

		for (int i = 0; i < 1000; i++) {
			BigInteger rnd = classUnderTest.createRandomNumber(BigInteger.valueOf(1), BigInteger.TEN);
			log.info("random number " + i + ":  " + rnd);
			assertTrue(rnd.compareTo(BigInteger.valueOf(1)) >= 0 && rnd.compareTo(BigInteger.TEN) <= 0);
		}
	}

	@Test
	@DisplayName("Test generate random number in range uniqueness")
	void createRandomNumberUnique() {

		assumeTrue(BaseTest.EXECUTE_INTENSIVE_TESTS);
		log.info("@Test: createRandomNumber ");
		int arraySize = 100;
		BigInteger[] rndArray = new BigInteger[arraySize];

		for (int i = 0; i < arraySize; i++) {
			BigInteger rnd =
					classUnderTest.createRandomNumber(BigInteger.valueOf(1), BigInteger.valueOf(1000000));
			rndArray[i] = rnd;
			log.info("random number " + i + ":  " + rnd);
			assertTrue(
					rnd.compareTo(BigInteger.valueOf(1)) >= 0
							&& rnd.compareTo(BigInteger.valueOf(1000000)) <= 0);
		}

		for (int i = 0; i < arraySize; i++) {
			BigInteger irnd = rndArray[i];
			for (int j = 0; j < arraySize; j++) {
				if (i != j) {
					BigInteger jrnd = rndArray[j];
					if (irnd.equals(jrnd)) {
						fail("Duplicate random number generated");
					}
				}
			}
		}
	}

	@Test
	@DisplayName("generate random number in range with max,min")
	void createRandomNumberWithMaxMin() {
		log.info("@Test: createRandomNumber ");
		int arraySize = 1000;
		BigInteger[] rndArray = new BigInteger[arraySize];

		for (int i = 0; i < arraySize; i++) {
			BigInteger rnd =
					classUnderTest.createRandomNumber(BigInteger.valueOf(1), BigInteger.valueOf(100));
			rndArray[i] = rnd;
			log.info("random number " + i + ":  " + rnd);
			assertTrue(
					rnd.compareTo(BigInteger.valueOf(1)) >= 0 && rnd.compareTo(BigInteger.valueOf(100)) <= 0);
		}
	}

	@Test
	@DisplayName("Test generate random number in range with max,min uniqueness")
	void createRandomNumberWithMaxMinUnique() {
		log.info("@Test: createRandomNumber ");

		for (int i = 0; i < 1000; i++) {
			BigInteger rnd = classUnderTest.createRandomNumber(BigInteger.TEN, BigInteger.ZERO);
			log.info("random number " + i + ":  " + rnd);
			assertTrue(rnd.compareTo(BigInteger.valueOf(0)) >= 0 && rnd.compareTo(BigInteger.TEN) <= 0);
		}
	}

	//  @Test
	//  @DisplayName("Test if an integer a is an element of QRN")
	//  void elementOfQRN() {
	//
	//    BigInteger qrn = BigInteger.valueOf(15);
	//    BigInteger modN = BigInteger.valueOf(77);
	//
	//    Boolean isQRN = classUnderTest.elementOfQRN(qrn, modN);
	//
	//    log.info("element of qrn: " + isQRN);
	//
	//    assertTrue(isQRN);
	//
	//    qrn = BigInteger.valueOf(14);
	//    modN = BigInteger.valueOf(77);
	//
	//    isQRN = classUnderTest.elementOfQRN(qrn, modN);
	//
	//    log.info("element of qrn: " + isQRN);
	//
	//    Assert.assertThat(isQRN, is(true));
	//  }

	//  @Test
	//  @DisplayName("Test if S is a generator of QRN")
	//  void verifySGeneratorOfQRN() {
	//
	//    BigInteger generatorS = BigInteger.valueOf(60);
	//    BigInteger modN = BigInteger.valueOf(77);
	//
	//    Boolean isGenerator = classUnderTest.verifySGeneratorOfQRN(generatorS, modN);
	//
	//    log.info("is generator of QRN " + isGenerator);
	//
	//    assertTrue(isGenerator);
	//  }

	@Test
	@DisplayName("generate random number with factors")
	void generateRandomNumberWithFactors() {

		log.info("@Test: generateRandomNumberWithFactors");
		BigInteger m;

		BigInteger factor;
		m = BigInteger.ONE;

		ArrayList<BigInteger> factors;

		if (BaseTest.EXECUTE_INTENSIVE_TESTS) {
			factors =
					classUnderTest.generateRandomPrimeWithFactors(
							new BigInteger(
									keyGenParameters.getL_gamma(), keyGenParameters.getL_pt(), new SecureRandom()));
		} else {
			factors =
					classUnderTest.generateRandomNumberWithFactors(
							new BigInteger(512, keyGenParameters.getL_pt(), new SecureRandom()));
		}

		log.info("@Test: rnd length: " + factors.size());

		for (int i = 0; i < factors.size(); i++) {
			factor = factors.get(i);
			log.info("@Test: factor " + i + " : " + factor);
			assertTrue(factor.isProbablePrime(80));
			m = m.multiply(factor);
		}

		log.info("@Test: m: " + m);

		//    log.info("@Test: m+1: " + m.add(BigInteger.ONE));
		//    log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
	}

	// TODO The random prime with factors test does not seem to terminate.
	// TODO smaller version to test case with 512
	@Test
	@DisplayName("generate random Prime number with factors")
	void generateRandomPrimeWithFactors() {

		BigInteger m;
		BigInteger factor;
		m = BigInteger.ONE;

		ArrayList<BigInteger> factors;

		if (BaseTest.EXECUTE_INTENSIVE_TESTS) {
			factors =
					classUnderTest.generateRandomPrimeWithFactors(
							new BigInteger(
									keyGenParameters.getL_gamma(), keyGenParameters.getL_pt(), new SecureRandom()));
		} else {
			factors =
					classUnderTest.generateRandomPrimeWithFactors(
							new BigInteger(512, keyGenParameters.getL_pt(), new SecureRandom()));
		}

		log.info("@Test: rnd length: " + factors.size());

		for (int i = 0; i < factors.size(); i++) {
			factor = factors.get(i);
			log.info("@Test: factor " + i + " : " + factor);
			assertTrue(factor.isProbablePrime(80));
			m = m.multiply(factor);
		}

		log.info("@Test: m: " + m);
		m = m.add(BigInteger.ONE);
		log.info("@Test: m+1: " + m.add(BigInteger.ONE));
		log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
		Boolean isPrime = m.isProbablePrime(80);
		assertTrue(isPrime);
	}

	@Test
	@DisplayName("get max number from a list")
	void getMaxNumber() {

		log.info("@Test: getMaxNumber");
		ArrayList<BigInteger> list =
				new ArrayList<BigInteger>(
						Arrays.asList(
								BigInteger.valueOf(20),
								BigInteger.valueOf(23),
								BigInteger.valueOf(19),
								BigInteger.valueOf(3)));

		assertEquals(BigInteger.valueOf(23), classUnderTest.getMaxNumber(list));
	}

	@Test
	@DisplayName("createZPSGenerator")
	void createZPSGenerator() {
		log.info("@Test: createZPSGenerator");
		// 1150 = 2x5x5x23

		//        ArrayList<BigInteger> primeFactors = new
		// ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(2), BigInteger.valueOf(5),
		// BigInteger.valueOf(23), BigInteger.valueOf(5)));

		// 10 = 2x5  (generators {2,6,7,8})

		for (int i = 0; i < 10; i++) {

			ArrayList<BigInteger> primeFactors =
					new ArrayList<BigInteger>(Arrays.asList(BigInteger.valueOf(2), BigInteger.valueOf(5)));

			BigInteger gamma, g;

			//        BigInteger rho = BigInteger.valueOf(383);
			BigInteger rho = BigInteger.valueOf(5);

			BigInteger m = BigInteger.probablePrime(keyGenParameters.getL_gamma(), new SecureRandom());

			gamma = BigInteger.valueOf(11); // classUnderTest.computeCommitmentGroupModulus(m);

			log.info("gamma: " + gamma);
			log.info("gamma bitlength: " + gamma.bitLength());
			assertNotNull(gamma);

			g = classUnderTest.createZPSGenerator(gamma, primeFactors);

			log.info("generator: " + g);

			assertNotNull(g);
			// g^rho mod gamma = 1 mod gamma
			//        assertEquals(g.modPow(classUnderTest.getRho(), gamma.add(BigInteger.ONE)),
			// BigInteger.ONE.mod(gamma.add(BigInteger.ONE)));
			assertThat(
					g,
					anyOf(
							is(BigInteger.valueOf(2)),
							is(BigInteger.valueOf(6)),
							is(BigInteger.valueOf(7)),
							is(BigInteger.valueOf(8))));
		}
	}

	@Test
		//  @RepeatedTest(10)
	void randomMinusPlusNumber() {
		int bitlength = 128;
		BigInteger max = NumberConstants.TWO.getValue().pow(bitlength).subtract(BigInteger.ONE);
		BigInteger min = NumberConstants.TWO.getValue().pow(bitlength).add(BigInteger.ONE).negate();
		BigInteger numb = classUnderTest.randomMinusPlusNumber(bitlength);
		log.info("number: " + numb);
		log.info("number bitlength: " + numb.bitLength());

		assertNotNull(numb);
		assertTrue(numb.compareTo(min) > 0 && numb.compareTo(max) < 0);
		assertTrue(numb.bitLength() == bitlength);
	}

	@Test
	void multiBaseExp() {

		List<BigInteger> bases = new ArrayList<BigInteger>();
		List<BigInteger> exponents = new ArrayList<BigInteger>();

		BigInteger modN = BigInteger.valueOf(77);
		BigInteger baseS = BigInteger.valueOf(60);
		BigInteger baseR = BigInteger.valueOf(58);
		bases.add(baseS);
		bases.add(baseR);

		BigInteger exp1 = BigInteger.valueOf(2);
		BigInteger exp2 = BigInteger.valueOf(3);
		exponents.add(exp1);
		exponents.add(exp2);

		BigInteger resultMultiBaseEx = classUnderTest.multiBaseExp(bases, exponents, modN);

		log.info("resultmultibase: " + resultMultiBaseEx);

		BigInteger result = baseS.modPow(exp1, modN).multiply(baseR.modPow(exp2, modN));
		log.info("result: " + result);

		assertEquals(result, resultMultiBaseEx);
	}

	@Test
	@DisplayName("Test generate prime [2^l_e, 2^l_e + 2^lPrime_e]")
	@RepeatedTest(
			value = 5,
			name = "{displayName} - repetition {currentRepetition} of {totalRepetitions}")
	void generatePrimeWithLength() {
		int minBitLength = keyGenParameters.getL_e();
		int maxBitLength = keyGenParameters.getL_prime_e();
		BigInteger min = NumberConstants.TWO.getValue().pow(minBitLength);
		BigInteger max = min.add(NumberConstants.TWO.getValue().pow(maxBitLength));
		BigInteger result = classUnderTest.generatePrimeWithLength(minBitLength, maxBitLength);

		log.info("l_e bitlength: " + keyGenParameters.getL_e());
		log.info("l_prime_e bitlength: " + keyGenParameters.getL_prime_e());
		log.info("min bitlength: " + min.bitLength());
		log.info("max bitlength: " + max.bitLength());
		log.info("result: " + result);
		log.info("result bitlength: " + result.bitLength());

		assertTrue(result.compareTo(min) > 0 && result.compareTo(max) < 0);
	}

	@Test
	@DisplayName("Test jacobi symbol")
	void computeJacobiSymbol() {
		BigInteger modN = BigInteger.valueOf(77);
		BigInteger number = BigInteger.valueOf(60);

		int result = GSUtils.computeJacobiSymbol(number, modN);
		log.info("result: " + result);

		assertEquals(1, result);
	}

	@Test
	@DisplayName("Test creating an element of ZNS")
	void createElementOfZNS() {
		BigInteger modN = BigInteger.valueOf(77);
		BigInteger number = BigInteger.valueOf(15);
		BigInteger element = classUnderTest.createElementOfZNS(modN);
		boolean res = element.gcd(modN).equals(BigInteger.ONE);

		assertTrue(res);
	}

	@Test
	@DisplayName("Test creating an element of ZNS with full bitlength")
	void createElementOfZNSWithFullBitlength() {

		BigInteger modN = BigInteger.valueOf(77);
		BigInteger number = BigInteger.valueOf(15);
		BigInteger element = classUnderTest.createElementOfZNS(modN);
		boolean res = element.gcd(modN).equals(BigInteger.ONE);

		assertTrue(res);
	}
	//  @Test
	//  @DisplayName("Test creating a QRN generator")
	//  //  @RepeatedTest(
	//  //      value = 10,
	//  //      name = "{displayName} - repetition {currentRepetition} of {totalRepetitions}")
	//  void createQRNGenerator() {
	//    BigInteger modN = BigInteger.valueOf(77);
	//    QRElement element = classUnderTest.createQRNGenerator(modN);
	//
	//    log.info("qrn generator: " + element);
	//    assertNotNull(element);
	//
	//    assertTrue(classUnderTest.verifySGeneratorOfQRN(element.getValue(), modN));
	//  }
	//
	//  @Test
	//  @DisplayName("Test creating a QRN element")
	//  //  @RepeatedTest(
	//  //      value = 10,
	//  //      name = "{displayName} - repetition {currentRepetition} of {totalRepetitions}")
	//  void createQRNElement() {
	//    BigInteger modN = BigInteger.valueOf(77);
	//
	//    QRElement element = classUnderTest.createQRNElement(modN);
	//
	//    log.info("qrn element: " + element);
	//    assertNotNull(element);
	//
	//    assertTrue(classUnderTest.elementOfQRN(element.getValue(), modN));
	//  }

	@Test
		//  @RepeatedTest(5)
	void computeHash() throws NoSuchAlgorithmException {

		List<String> list = new ArrayList<String>();
		list.add("10");
		list.add("15");

		log.info("list: " + list);
		BigInteger hs = classUnderTest.computeHash(list, keyGenParameters.getL_H());
		log.info("hash: " + hs);
		log.info("bitlength: " + hs.bitLength());

		BigInteger hash =
				new BigInteger(
						"67541942384023015311168229225888487473300699144727519117422423493167587604356");
		assertNotNull(hs);

		assertEquals(hash, hs);
		assertEquals(keyGenParameters.getL_H(), hs.bitLength());
	}

	@Test
	void multiBaseExpMap() {
		Map<URN, GroupElement> bases = new HashMap<>();
		GroupElement gp1 = new QRElement(new QRGroupN(BigInteger.TEN), BigInteger.valueOf(13));
		bases.put(URN.createUnsafeZkpgsURN("test.base.1"), gp1);
		GroupElement gp2 = new QRElement(new QRGroupN(BigInteger.TEN), BigInteger.valueOf(29));
		bases.put(URN.createUnsafeZkpgsURN("test.base.2"), gp2);

		Map<URN, BigInteger> exponents = new HashMap<>();
		BigInteger exp1 = BigInteger.valueOf(2223523);
		exponents.put(URN.createUnsafeZkpgsURN("test.expo.1"), exp1);

		BigInteger exp2 = BigInteger.valueOf(33234239);
		exponents.put(URN.createUnsafeZkpgsURN("test.expo.2"), exp2);
		BigInteger multiresult = classUnderTest.multiBaseExpMap(bases, exponents, BigInteger.TEN);
		GroupElement res1 = gp2.modPow(exp2);
		GroupElement res2 = gp1.modPow(exp1);
		GroupElement result = res1.multiply(res2);

		assertEquals(result.getValue(), multiresult);
	}

	@Test
		//  @RepeatedTest(10)
	void generateRandomSafePrime() {
		if (!BaseTest.EXECUTE_INTENSIVE_TESTS) {
			// test generating a random safe prime with 512 modulus bitlength
			keyGenParameters =
					KeyGenParameters.createKeyGenParameters(
							512, 1632, 80, 256, 1, 597, 120, 2724, 80, 256, 80, 80);
		}

		SafePrime prime = classUnderTest.generateRandomSafePrime(keyGenParameters);
		log.info("prime bitlength: " + prime.getSafePrime().bitLength());
		assertEquals(keyGenParameters.getL_n() / 2, prime.getSafePrime().bitLength());
		assertTrue(prime.getSafePrime().isProbablePrime(80));
	}

	@Test
	void isPrime() {

		BigInteger testPrime = classUnderTest.generateRandomPrime(10);
		assertTrue(classUnderTest.isPrime(testPrime));
	}

	@Test
		//  @RepeatedTest(10)
	void generateRandomPrime() {

		int bitlength = 128;
		BigInteger prime = classUnderTest.generateRandomPrime(bitlength);
		log.info("prime bitlength: " + prime.bitLength());
		assertEquals(128, prime.bitLength());
		assertTrue(prime.isProbablePrime(keyGenParameters.getL_pt()));
	}

	@Test
	@RepeatedTest(10)
	@DisplayName("Test generate a prime in range when min is a negative number")
	void generateRandomPrimeInRangeWithNegativeMin() {
		log.info("generate random prime in range");
		BigInteger min = keyGenParameters.getLowerBoundV();
		BigInteger max = keyGenParameters.getUpperBoundV();
		BigInteger primeV = classUnderTest.generatePrimeInRange(min, max);

		assertNotNull(primeV);
		log.info("prime number: " + primeV);
		assertTrue(primeV.isProbablePrime(keyGenParameters.getL_pt()));
		assertTrue(
				(primeV.compareTo(this.keyGenParameters.getLowerBoundV()) > 0)
						&& (primeV.compareTo(this.keyGenParameters.getUpperBoundV()) < 0));
	}

	@Test
	@RepeatedTest(10)
	@DisplayName("Test generate a prime in range when min is a positive number")
	void generateRandomPrimeInRangeWithPositiveMin() {
		BigInteger min = keyGenParameters.getLowerBoundE();
		BigInteger max = keyGenParameters.getUpperBoundE();
		BigInteger primeE = classUnderTest.generatePrimeInRange(min, max);

		assertNotNull(primeE);
		log.info("prime number: " + primeE);
		assertTrue(primeE.isProbablePrime(keyGenParameters.getL_pt()));

		assertTrue(
				(primeE.compareTo(this.keyGenParameters.getLowerBoundE()) > 0)
						&& (primeE.compareTo(this.keyGenParameters.getUpperBoundE()) < 0));
	}

	@Test
	void testGetUpperPMBound() {
		BigInteger bound1024 = classUnderTest.getUpperPMBound(1024);
		assertEquals(NumberConstants.TWO.getValue().pow(1024).subtract(BigInteger.ONE), bound1024);

		assertSame(
				bound1024,
				classUnderTest.getUpperPMBound(1024),
				"A second retrieval of the same bound did not retrieve the very same object.");

		BigInteger bound2048 = classUnderTest.getUpperPMBound(2048);
		assertEquals(NumberConstants.TWO.getValue().pow(2048).subtract(BigInteger.ONE), bound2048);

		assertSame(
				bound2048,
				classUnderTest.getUpperPMBound(2048),
				"A second retrieval of the same bound did not retrieve the very same object.");

		BigInteger bound2049 = classUnderTest.getUpperPMBound(2049);
		assertEquals(NumberConstants.TWO.getValue().pow(2049).subtract(BigInteger.ONE), bound2049);

		assertSame(
				bound2049,
				classUnderTest.getUpperPMBound(2049),
				"A second retrieval of the same bound did not retrieve the very same object.");
	}

	@Test
	void testGetLowerPMBound() {
		BigInteger nbound1024 = classUnderTest.getLowerPMBound(1024);
		assertEquals(
				(NumberConstants.TWO.getValue().pow(1024)).negate().add(BigInteger.ONE), nbound1024);

		assertSame(
				nbound1024,
				classUnderTest.getLowerPMBound(1024),
				"A second retrieval of the same bound did not retrieve the very same object.");

		BigInteger nbound2048 = classUnderTest.getLowerPMBound(2048);
		assertEquals(
				(NumberConstants.TWO.getValue().pow(2048)).negate().add(BigInteger.ONE), nbound2048);

		assertSame(
				nbound2048,
				classUnderTest.getLowerPMBound(2048),
				"A second retrieval of the same bound did not retrieve the very same object.");

		BigInteger nbound2049 = classUnderTest.getLowerPMBound(2049);
		assertEquals(
				(NumberConstants.TWO.getValue().pow(2049)).negate().add(BigInteger.ONE), nbound2049);

		assertSame(
				nbound2049,
				classUnderTest.getLowerPMBound(2049),
				"A second retrieval of the same bound did not retrieve the very same object.");
	}

	@Test
	void testUpperPMBoundsIllegalBitLength() {
		try {
			classUnderTest.getUpperPMBound(0);
			classUnderTest.getUpperPMBound(-1);
		} catch (RuntimeException e) {
			return;
		}
		fail("The getUpperPMBounds method should have thrown a RuntimeException on inputs <= 0");
	}

	@Test
	void testLowerPMBoundsIllegalBitLength() {
		try {
			classUnderTest.getLowerPMBound(0);
			classUnderTest.getLowerPMBound(-1);
		} catch (RuntimeException e) {
			return;
		}
		fail("The getLowerPMBounds method should have thrown a RuntimeException on inputs <= 0");
	}

	@Test
	@RepeatedTest(10)
	void testIsInPMRange() {
		BigInteger upperBound = NumberConstants.TWO.getValue().pow(1024).subtract(BigInteger.ONE);

		assertTrue(
				classUnderTest.isInPMRange(upperBound, 1024),
				"isInPMRange() did not correctly consider the upper bound in 1024 range.");

		BigInteger lowerBound = (NumberConstants.TWO.getValue().pow(1024)).negate().add(BigInteger.ONE);

		assertTrue(
				classUnderTest.isInPMRange(lowerBound, 1024),
				"isInPMRange() did not correctly consider the lower bound in 1024 range.");

		BigInteger testIn = classUnderTest.createRandomNumber(1023);

		assertTrue(
				classUnderTest.isInPMRange(testIn, 1024),
				"isInPMRange() did not correctly consider a 1023-bits number in 1024 range.");

		BigInteger testOut =
				classUnderTest.createRandomNumber(2048).add(NumberConstants.TWO.getValue().pow(1025));

		assertFalse(
				classUnderTest.isInPMRange(testOut, 1024),
				"isInPMRange() did not correctly reject a number greater than range.");

		BigInteger testOutN =
				(classUnderTest
						.createRandomNumber(2048)
						.add(NumberConstants.TWO.getValue().pow(1025))
						.negate());

		assertFalse(
				classUnderTest.isInPMRange(testOutN, 1024),
				"isInPMRange() did not correctly reject a number less than range.");
	}

	@Test
	@DisplayName("Test splitting a hex string in chunks")
	void splitHexString() {
		final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
		BigInteger number = new BigInteger(N_G, 16);
		log.info("number length: " + number.bitLength());
		byte[] bitarray = number.toByteArray();
		log.info("bit array length: " + bitarray.length);

		String hexString = number.toString(16).toUpperCase();
		assertEquals(hexString, N_G);
		log.info("hex string: " + hexString);
		log.info("hex string length: " + hexString.length());
		List<BigInteger> strings = classUnderTest.splitHexString(hexString, 28);

		log.info("strings: " + Arrays.toString(strings.toArray()));
		log.info("strings length: " + strings.size());
		log.info("strings 0 LengthL :" + strings.get(0).bitLength());

		assertEquals(15, strings.size());
	}


	@Test
	@Disabled
	@DisplayName("Test joining hex string array and converting it to big integer")
	void joinHexString() {
		final String N_G = "23998E2A7765B6C913C0ED47D9CB3AC03DB4597D1C4438D61C9FD3418F3D78FFADC59E451FE25A28DD91CEDC59E40980BAE8A176EBEECE412F13466862BFFC3077BB9D26FEB8244ACD4B8D8C868E0095E6AC4122B148FE6F398073111DDCAB8194531CFA8D487B70223CF750E653190732F8BA2A2F7D2BFE2ED175A936BBC7671FC0BB9E45276F81A527F06ABBCC0AFFEDC994BF66D9EB69CC7B61F691FFAB1F78BC6E890A92E332E49519056F502F07206E69E6C182B135D785101DCA408E4F484768854CEAFA0C76355F47";
		BigInteger number = new BigInteger(N_G, 16);
		log.info("number length: " + number.bitLength());
		byte[] byteArray = number.toByteArray();
		log.info("bit arraay length: " + byteArray.length);

		String binString = number.toString(16).toUpperCase();
		assertEquals(N_G, binString);
		log.info("bin string: " + binString);
		log.info("binary string length: " + binString.length());
		List<BigInteger> strings = classUnderTest.splitHexString(binString, 32);
		log.info("strings length: " + strings.size());
		List<BigInteger> bigArray = new ArrayList<BigInteger>();

		for (int i = 0; i < strings.size(); i++) {
			log.info("index: " + i + " st: " + strings.get(i));
			bigArray.add(strings.get(i));
		}

		log.info("bigArray size: " + bigArray.size());
		for (BigInteger bigInteger : bigArray) {
			log.info("bigInteger: " + bigInteger);
			log.info("biginteger length: " + bigInteger.bitLength());
		}
		String el;
		List<BigInteger> bigArrayConv = new ArrayList<BigInteger>();
		for (int i = 0; i < bigArray.size(); i++) {
			log.info("biginteger: " + bigArray.get(i));
			BigInteger big = bigArray.get(i);
			big.toByteArray();
			el = bigArray.get(i).toString(16).toUpperCase();
			log.info("el: " + el);
			log.info("string: " + strings.get(i));
			BigInteger conv = strings.get(i);
			bigArrayConv.add(i, conv);
			log.info("biginteger conv: " + conv);
			log.info("biginteger conv length: " + conv.bitLength());
			log.info("index: " + i);

			assertEquals(el, strings.get(i));
			assertEquals(big, conv);
		}

		List<BigInteger> stringsFromBigInteger = new ArrayList<>();

		for (BigInteger bigInteger : bigArray) {

			stringsFromBigInteger.add(bigInteger);
		}

		BigInteger str = classUnderTest.joinHexString(stringsFromBigInteger);
		assertEquals(str, binString);
		log.info("join str : " + str);
//		BigInteger res = new BigInteger(str);
//		assertEquals(res, number);
//		assertArrayEquals(bigArray.toArray(), bigArrayConv.toArray());
	}
}
