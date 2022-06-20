package uk.ac.ncl.cascade.keys;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import java.io.IOException;
import java.util.logging.Logger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class ExtendedKeyPairTest {
  private Logger log = GSLoggerConfiguration.getGSlog();
  private KeyGenParameters keyGenParameters;
  private GraphEncodingParameters graphEncodingParameters;
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
  }
  //TODO Why is setupEncoding() called in every test?

  @Test
  void getExtendedPublicKey() throws EncodingException {
    log.info("@Test: extended public key");

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getBases());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getLabelRepresentatives());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getVertexRepresentatives());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getPublicKey());
  }

  @Test
  void getExtendedPrivateKey() throws EncodingException {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPrivateKey());
  }

  @Test
  void getPublicKey() throws EncodingException {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey());
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getPublicKey());
  }

  @Test
  void getPrivateKey() throws EncodingException {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPrivateKey());
    assertNotNull(extendedKeyPair.getExtendedPrivateKey().getPrivateKey());
  }

  @Test
  void setupEncoding() throws EncodingException {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
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
  void generateBases() throws EncodingException {

    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getBases());
  }

  @Test
  void getLabelRepresentatives() throws EncodingException {
    assertNotNull(extendedKeyPair);
    assertNotNull(extendedKeyPair.getPublicKey());
    assertNotNull(extendedKeyPair.getPrivateKey());

    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    assertNotNull(extendedKeyPair.getExtendedPublicKey().getLabelRepresentatives());
  }
}
