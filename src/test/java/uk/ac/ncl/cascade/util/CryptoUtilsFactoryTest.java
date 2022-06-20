package uk.ac.ncl.cascade.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.logging.Logger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFactory;
import uk.ac.ncl.cascade.zkpgs.util.GSUtils;
import uk.ac.ncl.cascade.zkpgs.util.INumberUtils;
import uk.ac.ncl.cascade.zkpgs.util.IdemixUtils;

/** Test CryptoUtilsFactory class */
@DisplayName("Testing CryptoUtilsFactory class")
class CryptoUtilsFactoryTest {
  private static final String GS = "GS";
  private static final String IDEMIX = "IDEMIX";
  private static final Logger log = Logger.getLogger(CryptoUtilsFactoryTest.class.getName());

  private CryptoUtilsFactory classUnderTest;

  @BeforeEach
  void setUp() {
    log.info("@BeforeEach: setUp()");
    classUnderTest = new CryptoUtilsFactory();
  }

  @Test
  @DisplayName("Test correct instance of util classes in factory")
  void getInstance() {

    log.info("@Test: getInstance()");
    assertNotNull(classUnderTest);
    assertAll(
        () -> {

          // Test if factory returns the correct class
          INumberUtils idemix = CryptoUtilsFactory.getInstance(IDEMIX);
          INumberUtils id = new IdemixUtils();

          assertNotNull(idemix);
          assertEquals("uk.ac.ncl.cascade.zkpgs.util.IdemixUtils",idemix.getClass().getCanonicalName() );
        },
        () -> {

          // Test if factory returns the correct class
          INumberUtils gs = CryptoUtilsFactory.getInstance(GS);
          GSUtils id = new GSUtils();
          assertEquals("uk.ac.ncl.cascade.zkpgs.util.GSUtils",gs.getClass().getCanonicalName() );
        },
        () -> {
          // Test factory when name is not correct
          INumberUtils nu = CryptoUtilsFactory.getInstance("demo");
          assertNotNull(nu);
          assertEquals("uk.ac.ncl.cascade.zkpgs.util.GSUtils", nu.getClass().getCanonicalName());
        });
  }

}
