package eu.prismacloud.primitives.grs.utils;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.grs.util.CryptoUtilsFactory;
import eu.prismacloud.primitives.grs.util.GSUtils;
import eu.prismacloud.primitives.grs.util.INumberUtils;
import eu.prismacloud.primitives.grs.util.IdemixUtils;
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
  void setUp() throws Exception {
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
          INumberUtils idemix = classUnderTest.getInstance("IDEMIX");
          INumberUtils id = new IdemixUtils();
          assertThat(id, instanceOf(idemix.getClass()));
        },
        () -> {

          // Test if factory returns the correct class
          INumberUtils gs = classUnderTest.getInstance("GS");
          GSUtils id = new GSUtils();
          assertThat(id, instanceOf(gs.getClass()));
        },
        () -> {
          // Test factory when name is not correct
          INumberUtils nu = classUnderTest.getInstance("demo");
          assertNull(nu);
        });
  }

  @AfterEach
  void tearDown() {}
}
