package uk.ac.ncl.cascade.util.crypto;

import static org.junit.Assert.fail;

import java.util.logging.Logger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.util.crypto.QRElementPQ;

@Disabled
class QRElementPQTest {
  private static final Logger log = Logger.getLogger(QRElementPQTest.class.getName());
  private QRElementPQ classUnderTest;

  @BeforeEach
  void setup() {}

  @AfterEach
  void tearDown() {}

  @Test
  void getXp() {
	  fail("Test not implemented yet.");
  }

  @Test
  void getXq() {
	  fail("Test not implemented yet.");
  }

  @Test
  void setPQRepresentation() {
	  fail("Test not implemented yet.");
  }

  @Test
  void getGroup() {
	  fail("Test not implemented yet.");
  }

  @Test
  void getValue() {
	  fail("Test not implemented yet.");
  }

  @Test
  void getOrder() {
	  fail("Test not implemented yet.");
  }

  @Test
  void modPow() {
	  fail("Test not implemented yet.");
  }

  @Test
  void multiply() {
	  fail("Test not implemented yet.");
    // TODO multiply using the CRT and randomization -> create elements in randoma and multiply them

  }
}
