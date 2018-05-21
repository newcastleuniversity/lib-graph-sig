package eu.prismacloud.primitives.grs.keys;

import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SignerPublicKeyTest {
  private static final Logger log = Logger.getLogger(SignerPublicKeyTest.class.getName());
  private GSSignerKeyPair gsk;

  @BeforeEach
  void setUp() {
    // classUnderTest = new GSSignerKeyPair();
    gsk = GSSignerKeyPair.KeyGen();
  }

  @AfterEach
  void tearDown() {}

  @Test
  void getN() {}

  @Test
  void getR_0() {}

  @Test
  void getS() {}

  @Test
  void getZ() {}
}
