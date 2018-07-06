package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JSONParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ExtendedKeyPairTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;

  @BeforeEach
  void setUp() {
    JSONParameters parameters = new JSONParameters();
    keyGenParameters = parameters.getKeyGenParameters();
    graphEncodingParameters = parameters.getGraphEncodingParameters();
    log.info("@Test: key generation");
    SignerKeyPair gsk = new SignerKeyPair();
    gsk.keyGen(keyGenParameters);
    assertNotNull(gsk);
    assertNotNull(gsk.getPrivateKey());
    assertNotNull(gsk.getPublicKey());
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
  }

  @Test
  void getExtendedPublicKey() {
    log.info("@Test: extended public key");

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getBases());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getLabelRepresentatives());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getVertexRepresentatives());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getPublicKey());
  }

  @Test
  void getExtendedPrivateKey() {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPrivateKey());
  }

  @Test
  void getPublicKey() {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getPublicKey());
  }

  @Test
  void getPrivateKey() {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPrivateKey());
    assertNotNull(extendedKeyPair.getExtendedPrivateKey().getPrivateKey());
  }

  @Test
  void graphEncodingSetup() {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.getGraphEncoding();
    assertNotNull(extendedKeyPair.getGraphEncoding());
  }

  @Test
  void getGraphEncoding() {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    assertNotNull(extendedKeyPair.getGraphEncoding());

    assertNotNull(extendedKeyPair.getGraphEncoding());
  }

  @Test
  void certifyPrimeRepresentatives() {}

  @Test
  void generateBases() {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getBases());
  }

  @Test
  void getLabelRepresentatives() {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getLabelRepresentatives());
  }
}
