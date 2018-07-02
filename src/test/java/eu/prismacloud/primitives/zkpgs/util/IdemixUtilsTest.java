package eu.prismacloud.primitives.zkpgs.util;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.crypto.CommitmentGroup;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class IdemixUtilsTest {
  private static final Logger log = Logger.getLogger(IdemixUtilsTest.class.getName());
  private IdemixUtils classUnderTest;

  @BeforeEach
  void setUp() {
    classUnderTest = new IdemixUtils();
  }

  @AfterEach
  void tearDown() {
    classUnderTest = null;
  }

  @Test
  void generateRandomSafePrime() {}

  @Test
  void generateSpecialRSAModulus() {}

  @Test
  void createQRNGenerator() {}

  @Test
  void createRandomNumber() {}

  @Test
  @DisplayName("Test generate commitment group")
  void generateCommitmentGroup(KeyGenParameters keyGenParameters) {
    log.info("@Test: generateCommitmentGroup");
    assertNotNull(classUnderTest);
    CommitmentGroup cg = classUnderTest.generateCommitmentGroup();
    log.info("rho: " + cg.getRho());
    log.info("gamma:  " + cg.getGamma());
    log.info("g: " + cg.getG());
    log.info("h: " + cg.getH());
    assertNotNull(cg);
  }
}