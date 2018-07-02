package eu.prismacloud.primitives.zkpgs.util;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.SpecialRSAMod;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Test GSUtils class */
@ExtendWith(MockitoExtension.class)
class GSUtilsTest {

  private static final Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GSUtils classUnderTest;

  @Mock private SpecialRSAMod specialRSAModMock;

  @Mock private GSUtils gsUtilsMock;

  @BeforeEach
  void setUp() {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    classUnderTest = new GSUtils();
  }

  @AfterEach
  void tearDown() {
    classUnderTest = null;
  }

  @Test
  @DisplayName("Test generate Special RSA modulus")
  void generateSpecialRSAModulus() {
    log.info("@Test: generateSpecialRSAModulus");
    SpecialRSAMod srm = classUnderTest.generateSpecialRSAModulus();
    assertNotNull(srm);
    assertEquals(srm.getN(), srm.getP().multiply(srm.getQ()));
  }

  @Test
  @DisplayName("Test generate Special RSA modulus for uniqueness")
  void generateUniqueSpecialRSAModulus() {
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
    log.info("@Test: createRandomNumber ");
    int arraySize = 1000;
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

  @Test
  @DisplayName("Test if an integer a is an element of QRN")
  void elementOfQRN() {

    BigInteger qrn = BigInteger.valueOf(15);
    BigInteger modN = BigInteger.valueOf(77);

    Boolean isQRN = classUnderTest.elementOfQRN(qrn, modN);

    log.info("element of qrn: " + isQRN);

    assertTrue(isQRN);

    qrn = BigInteger.valueOf(14);
    modN = BigInteger.valueOf(77);

    isQRN = classUnderTest.elementOfQRN(qrn, modN);

    log.info("element of qrn: " + isQRN);

    assertFalse(isQRN);
  }

  @Test
  @DisplayName("Test if S is a generator of QRN")
  void verifySGeneratorOfQRN() {
    SpecialRSAMod specialRSAMod = classUnderTest.generateSpecialRSAModulus();
    log.info("specialrsa mod : " + specialRSAMod.getN());

    BigInteger generatorS = BigInteger.valueOf(60);
    BigInteger modN = BigInteger.valueOf(77);

    Boolean isGenerator = classUnderTest.verifySGeneratorOfQRN(generatorS, modN);

    log.info("is generator of QRN " + isGenerator);

    assertTrue(isGenerator);
  }

  @Test
  @DisplayName("generate random number with factors")
  void generateRandomNumberWithFactors() {

    log.info("@Test: generateRandomNumberWithFactors");
    BigInteger m;

    BigInteger factor;
    m = BigInteger.ONE;

    ArrayList<BigInteger> factors;

    //        factors = classUnderTest.generateRandomNumberWithFactors(BigInteger.valueOf(10109));
    factors =
        classUnderTest.generateRandomPrimeWithFactors(
            new BigInteger(
                keyGenParameters.getL_gamma(), keyGenParameters.getL_pt(), new SecureRandom()));
    log.info("@Test: rnd length: " + factors.size());

    for (int i = 0; i < factors.size(); i++) {
      factor = factors.get(i);
      log.info("@Test: factor " + i + " : " + factor);
      assertTrue(GSUtils.isPrime(factor));
      m = m.multiply(factor);
    }

    log.info("@Test: m: " + m);

    log.info("@Test: m+1: " + m.add(BigInteger.ONE));
    log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
  }

  @Test
  @DisplayName("generate Prime number with factors")
  void generateRandomPrimeWithFactors() {

    BigInteger m;
    BigInteger factor;
    m = BigInteger.ONE;

    ArrayList<BigInteger> factors;

    factors =
        classUnderTest.generateRandomPrimeWithFactors(
            new BigInteger(
                keyGenParameters.getL_gamma(), keyGenParameters.getL_pt(), new SecureRandom()));

    log.info("@Test: rnd length: " + factors.size());

    for (int i = 0; i < factors.size(); i++) {
      factor = factors.get(i);
      log.info("@Test: factor " + i + " : " + factor);
      assertTrue(GSUtils.isPrime(factor));
      m = m.multiply(factor);
    }

    log.info("@Test: m: " + m);

    log.info("@Test: m+1: " + m.add(BigInteger.ONE));
    log.info("@Test: m+1 length: " + m.add(BigInteger.ONE).bitLength());
    assertTrue(GSUtils.isPrime(m.add(BigInteger.ONE)));
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
  void randomMinusPlusNumber() {

    for (int i = 0; i < 100; i++) {
      BigInteger numb = classUnderTest.randomMinusPlusNumber(4);
      log.info("number: " + numb);
      log.info("number bitlength: " + numb.bitLength());

      assertNotNull(numb);
      assertTrue(numb.bitLength() <= 4);

      assertTrue(
          numb.compareTo(BigInteger.valueOf(-16)) > 0
              && numb.compareTo(BigInteger.valueOf(16)) < 0);
    }
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
    int minBitLength = 2;
    int maxBitLength = 4;

    BigInteger result = classUnderTest.generatePrimeWithLength(minBitLength, maxBitLength);

    log.info("result: " + result);
    log.info("bitlength: " + result.bitLength());

    assertTrue(
        result.compareTo(BigInteger.valueOf(4)) >= 0
            && result.compareTo(BigInteger.valueOf(20)) <= 0);
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
  @DisplayName("Test creating a QRN generator")
  @RepeatedTest(
      value = 10,
      name = "{displayName} - repetition {currentRepetition} of {totalRepetitions}")
  void createQRNGenerator() {
    BigInteger modN = BigInteger.valueOf(77);
    QRElement element = classUnderTest.createQRNGenerator(modN);

    log.info("qrn generator: " + element);
    assertNotNull(element);

    assertTrue(classUnderTest.verifySGeneratorOfQRN(element.getValue(), modN));
  }

  @Test
  @DisplayName("Test creating a QRN element")
  @RepeatedTest(
      value = 10,
      name = "{displayName} - repetition {currentRepetition} of {totalRepetitions}")
  void createQRNElement() {
    BigInteger modN = BigInteger.valueOf(77);

    QRElement element = classUnderTest.createQRNElement(modN);

    log.info("qrn element: " + element);
    assertNotNull(element);

    assertTrue(classUnderTest.elementOfQRN(element.getValue(), modN));
  }

  @Test
  @RepeatedTest(5)
  void computeHash() throws NoSuchAlgorithmException {

    List<String> list = new ArrayList<String>();
    list.add("10");
    list.add("15");

    log.info("list: " + list);
    BigInteger hs = classUnderTest.computeHash(list, keyGenParameters.getL_H());
    log.info("hash: " + hs);
    log.info("bitlength: "  + hs.bitLength());

    BigInteger hash =
        new BigInteger(
            "67541942384023015311168229225888487473300699144727519117422423493167587604356");
    assertNotNull(hs);

    assertEquals(hash, hs);
    assertEquals(keyGenParameters.getL_H(), hs.bitLength());

     String hasttext = String.format("%040x", hs);
     log.info(hs.toString(16));
     BigInteger hashB = new BigInteger(hasttext);
     log.info("string bitlength: " + hashB.bitLength());

  }
}