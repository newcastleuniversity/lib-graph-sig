package eu.prismacloud.primitives.zkpgs.util;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

/** Test CryptoUtilsFactory class */
@RunWith(JUnitPlatform.class)
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

  //    @ParameterizedTest(name = "run #{index} with [{arguments}]")
  //    @ValueSource(strings = {"IDEMIX", "GS"})
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
          assertThat(id, instanceOf(idemix.getClass()));
        },
        () -> {

          // Test if factory returns the correct class
          INumberUtils gs = CryptoUtilsFactory.getInstance(GS);
          GSUtils id = new GSUtils();
          assertThat(id, instanceOf(gs.getClass()));
        },
        () -> {
          // Test factory when name is not correct
          INumberUtils nu = CryptoUtilsFactory.getInstance("demo");
          assertNotNull(nu);
          assertEquals("eu.prismacloud.primitives.zkpgs.util.GSUtils", nu.getClass().getCanonicalName());
        });
  }

  @AfterEach
  void tearDown() {}
}
