package eu.prismacloud.primitives.zkpgs.util.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.math.BigInteger;
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
  private static KeyGenParameters keyGenParameters;
  private SafePrime classUnderTest;

  @BeforeAll
  public static void init() {
    log.info("@BeforeAll: init()");
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
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
  @DisplayName("Generate Safe Prime")
  void generateRandomSafePrime() {
    log.info("@Test: generateSafePrime()");
    assertNotNull(classUnderTest);
    SafePrime sf = classUnderTest.generateRandomSafePrime(keyGenParameters);
    assertNotNull(sf);
    assertTrue(sf.getSafePrime().isProbablePrime(keyGenParameters.getL_pt()));
    assertTrue(sf.getSophieGermain().isProbablePrime(keyGenParameters.getL_pt()));
    //        assertEquals(sf.a,new BigInteger("2").multiply(sf.a_prime).add(new BigInteger("1")));

  }

}
