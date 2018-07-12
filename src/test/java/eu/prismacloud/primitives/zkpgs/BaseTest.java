package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.FilePersistenceUtil;
import java.io.IOException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Base test class for using persisted SignerKeyPair */
@TestInstance(Lifecycle.PER_CLASS)
public class BaseTest {
  /** flag to execute performance intensive tests */
  public static final Boolean EXECUTE_INTENSIVE_TESTS = false;
  public static final String MODULUS_BIT_LENGTH = "2048";
  
  private KeyGenParameters keyGenParameters;
  private SignerKeyPair gsk;

  public KeyGenParameters getKeyGenParameters() {
    return this.keyGenParameters;
  }

  public GraphEncodingParameters getGraphEncodingParameters() {
    return this.graphEncodingParameters;
  }

  private GraphEncodingParameters graphEncodingParameters;

  @BeforeAll
  public void setup() {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
  }

  @ParameterizedTest(name = "{index} => bitLength=''{0}''")
  @ValueSource(strings = {"2048"})
  public void shouldCreateASignerKeyPair(String bitLength)
      throws IOException, ClassNotFoundException {

    if (bitLength.equals("2048")) {
      FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
      gsk = (SignerKeyPair) persistenceUtil.read("SignerKeyPair-" + bitLength + ".ser");
    } else {
      gsk.keyGen(keyGenParameters);
    }

    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
  }

  public SignerKeyPair getSignerKeyPair() {
    return gsk;
  }
}
