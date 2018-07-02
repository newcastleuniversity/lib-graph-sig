package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SignerPublicKeyTest {
  private static final Logger log = Logger.getLogger(SignerPublicKeyTest.class.getName());
  private SignerKeyPair gsk;
  private KeyGenParameters keyGenParameters;

  @BeforeEach
  void setUp() {
    // classUnderTest = new GSSignerKeyPair();
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();

    gsk = SignerKeyPair.KeyGen(keyGenParameters);
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
