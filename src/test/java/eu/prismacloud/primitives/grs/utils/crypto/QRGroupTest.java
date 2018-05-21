package eu.prismacloud.primitives.grs.utils.crypto;

import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test QRGroup */
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
  void getOrder() {}

  @Test
  @DisplayName("Test get Generator of QRGroup")
  void getGenerator() {}

  @Test
  @DisplayName("Test create a generator for QRGroup")
  void createGenerator() {}

  @Test
  @DisplayName("Test element for membership in QRGroup")
  void isElement() {}

  @Test
  void getModulus() {}
}
