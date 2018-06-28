package eu.prismacloud.primitives.grs.util;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFactory;
import eu.prismacloud.primitives.zkpgs.util.GSUtils;
import eu.prismacloud.primitives.zkpgs.util.INumberUtils;
import eu.prismacloud.primitives.zkpgs.util.IdemixUtils;
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
          INumberUtils idemix = CryptoUtilsFactory.getInstance("IDEMIX");
          INumberUtils id = new IdemixUtils();
          assertThat(id, instanceOf(idemix.getClass()));
        },
        () -> {

          // Test if factory returns the correct class
          INumberUtils gs = CryptoUtilsFactory.getInstance("GS");
          GSUtils id = new GSUtils();
          assertThat(id, instanceOf(gs.getClass()));
        },
        () -> {
          // Test factory when name is not correct
          INumberUtils nu = CryptoUtilsFactory.getInstance("demo");
          assertNull(nu);
        });
  }

  @AfterEach
  void tearDown() {}
}
