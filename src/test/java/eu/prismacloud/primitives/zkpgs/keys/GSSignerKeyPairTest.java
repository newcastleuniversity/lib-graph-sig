package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElementPQ;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Test Signer Key Pair */
class SignerKeyPairTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private SignerKeyPair gsk;
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private QRElementPQ baseS;

  @BeforeEach
  void setUp() {

    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
  }

  @Test
  @DisplayName("Test key generation")
  void keyGen() {
    log.info("@Test: key generation");
    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);
    SignerPublicKey pk = gsk.getPublicKey();

    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
  }

  @Test
  @DisplayName("Test base S")
  void testBaseS() {
    log.info("@Test: baseS");
    keyGen();

    baseS = (QRElementPQ) gsk.getPublicKey().getBaseS();
    assertNotNull(baseS);
  }

  @Test
  @DisplayName("Test key generation 10 times")
  void keyGen10times() {
    log.info("@Test: keyGen10times ");
    SignerKeyPair gsk = new SignerKeyPair();
    for (int i = 0; i < 10; i++) {
      gsk.keyGen(keyGenParameters);
      assertNotNull(gsk);
    }
  }

  @Test
  void generateKeySignature() {}

  @Test
  void getPrivateKey() {
    log.info("@Test: getPrivateKey");
    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);
    assertNotNull(gsk.getPrivateKey());

    assertNotNull(gsk.getPrivateKey().getpPrime());
    assertTrue(gsk.getPrivateKey().getpPrime().isProbablePrime(80));

    assertNotNull(gsk.getPrivateKey().getqPrime());
    assertTrue(gsk.getPrivateKey().getqPrime().isProbablePrime(80));

    assertNotNull(gsk.getPrivateKey().getX_r());
    assertNotNull(gsk.getPrivateKey().getX_r0());
    assertNotNull(gsk.getPrivateKey().getX_rZ());
  }

  @Test
  void getPublicKey() {
    log.info("@Test: getPublickKey");
    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);
    assertNotNull(gsk.getPublicKey());
  }
}
