package eu.prismacloud.primitives.zkpgs.util.crypto;

import static org.junit.Assert.fail;

import java.util.logging.Logger;

import org.junit.Ignore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test QRGroup */
@Disabled
class QRGroupTest {
  private static final Logger log = Logger.getLogger(QRGroupTest.class.getName());
  private QRGroupPQ classUnderTest;

  @BeforeEach
  void setUp() {
    //        classUnderTest = new QRGroup();
  }

  @AfterEach
  void tearDown() {}

  @Test
  @DisplayName("Test getOrder of QRGroup")
  void getOrder() {
	  fail("Test not implemented yet.");
  }

  @Test
  @DisplayName("Test get Generator of QRGroup")
  void getGenerator() {
	  fail("Test not implemented yet.");
  }

  @Test
  @DisplayName("Test create a generator for QRGroup")
  void createGenerator() {
	  fail("Test not implemented yet.");
  }

  @Test
  @DisplayName("Test element for membership in QRGroup")
  void isElement() {
	  fail("Test not implemented yet.");
  }

  @Test
  void getModulus() {
	  fail("Test not implemented yet.");
  }
}
