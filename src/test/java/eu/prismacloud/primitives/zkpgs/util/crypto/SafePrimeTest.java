package eu.prismacloud.primitives.zkpgs.util.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** Test SafePrime class */
@RunWith(JUnitPlatform.class)
@DisplayName("Testing Safe Prime class")
class SafePrimeTest {
  private static final Logger log = Logger.getLogger(SafePrimeTest.class.getName());

  private KeyGenParameters keyGenParameters;
  private SafePrime classUnderTest;

  @BeforeAll
  public static void init() {
    // Do something before ANY test is run in this class
    log.info("@BeforeAll: init()");
  }

  @AfterAll
  public static void done() {
    // Do something after ALL tests in this class are run
    log.info("@AfterAll: done()");
  }

  @BeforeEach
  public void setUp() throws Exception {

    log.info("@BeforeEach: setUp()");

    classUnderTest = new SafePrime();
  }

  @AfterEach
  public void tearDown() throws Exception {
    log.info("@AfterEach: tearDown()");
    classUnderTest = null;
  }

  @Test
  @Disabled
  @DisplayName("A disabled test")
  void testNotRun() {
    log.info("This test will not run");
  }

  //    @Test
  //    @DisplayName("Generate Prime number")
  //    public void testGeneratePrime() {
  //        log.info("@Test: generateRandomPrime()");
  //        assertNotNull(classUnderTest);
  //        assertAll(
  //                () -> {
  //                    // Test #1 check if return value is probable prime
  //                    SafePrime safePrime = classUnderTest.generateRandomSafePrime();
  //                    System.out.println("safePrime 1 = " + safePrime.getSafePrime());
  //
  // assertTrue(safePrime.getSafePrime().isProbablePrime(KeyGenParameters.l_pt.getValue()));
  //                    System.out.println(("sophieGermain 1 = " + safePrime.getSophieGermain()));
  //
  // assertTrue((safePrime.getSophieGermain().isProbablePrime(KeyGenParameters.l_pt.getValue())));
  //                }
  //                ,
  //                () -> {
  //                    // Test #2 check if return value is probable prime
  //                    BigInteger actualSum = classUnderTest.generateRandomPrime();
  //                    System.out.println("actualSum 2 = " + actualSum);
  //                    assertTrue(actualSum.isProbablePrime(KeyGenParameters.l_pt.getValue()));
  //                },
  //                () -> {
  //                    // Test #3 check if return value is probable prime
  //                    BigInteger actualSum = classUnderTest.generateRandomPrime();
  //                    System.out.println("actualSum 3 = " + actualSum);
  //                    assertTrue(actualSum.isProbablePrime(KeyGenParameters.l_pt.getValue()));
  //                });
  //    }

  @Test
  @DisplayName("Generate Safe Prime")
  void generateRandomSafePrime() {
    log.info("@Test: generateSafePrime()");
    assertNotNull(classUnderTest);
    SafePrime sf = classUnderTest.generateRandomSafePrime();
    assertNotNull(sf);
    assertTrue(sf.getSafePrime().isProbablePrime(keyGenParameters.getL_pt()));
    assertTrue(sf.getSophieGermain().isProbablePrime(keyGenParameters.getL_pt()));
    //        assertEquals(sf.a,new BigInteger("2").multiply(sf.a_prime).add(new BigInteger("1")));

  }

  //    @Test
  //    @DisplayName("Generate a safe Prime with IDEMIX")
  //    void generateRandomSafePrimeIDEMIX(){
  //        log.info("@Test: generateSafePrimeIDEMIX()");
  //        assertNotNull(classUnderTest);
  //        SafePrime sf = classUnderTest.generateSafePrimeIdemix();
  //        log.info("p: " + sf.a);
  //        log.info("length: " + sf.a.bitLength());
  //        assertNotNull(sf);
  //        assertTrue(sf.a.isProbablePrime(KeyGenParameters.l_pt.getValue()));
  //
  //    }

  @org.junit.jupiter.api.Test
  void isPrime() {}
}
