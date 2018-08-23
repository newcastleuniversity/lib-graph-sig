package eu.prismacloud.primitives.zkpgs.keys;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
class ExtendedPublicKeyTest {

  private KeyGenParameters keyGenParameters;
  private SignerKeyPair gsk;
  private GraphEncodingParameters graphEncodingParameters;
  private ExtendedKeyPair extendedKeyPair;
  private ExtendedPublicKey extendedPublicKey;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.graphEncodingSetup();
    extendedKeyPair.createExtendedKeyPair();
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
  }

  @Test
  @DisplayName("Test creation of ExtentedPublicKey")
  void testExtendedPublicKey() {
    assertNotNull(extendedPublicKey);
  }

  @Test
  void getPublicKey() {
    SignerPublicKey signerPublicKey = extendedPublicKey.getPublicKey();
    assertNotNull(signerPublicKey);
  }

  @Test
  void getBases() {
    Map<URN, BaseRepresentation> bases = extendedPublicKey.getBases();
    assertNotNull(bases);
    assertTrue(bases.size() > 0);
  }

  @Test
  void getBaseCollection() {
    BaseCollection bases = extendedPublicKey.getBaseCollection();
    assertNotNull(bases);
    assertTrue(bases.size() > 0);
  }

  @Test
  void getLabelRepresentatives() {
    Map<URN, BigInteger> labels = extendedPublicKey.getLabelRepresentatives();
    assertNotNull(labels);
  }

  @Test
  void getVertexRepresentatives() {
    Map<URN, BigInteger> vertexRepresentatives = extendedPublicKey.getLabelRepresentatives();
    assertNotNull(vertexRepresentatives);
  }

  @Test
  void getKeyGenParameters() {
    KeyGenParameters keyGenParameters = extendedPublicKey.getKeyGenParameters();
    assertNotNull(keyGenParameters);
  }

  @Test
  void getGraphEncodingParameters() {
    GraphEncodingParameters graphEncodingParameters =
        extendedPublicKey.getGraphEncodingParameters();
    assertNotNull(graphEncodingParameters);
  }

  @Test
  void computeChallengeContext() {
    List<String> challengeList = extendedPublicKey.computeChallengeContext();
    assertNotNull(challengeList);
    assertTrue(challengeList.size() > 0);
  }

  @Test
  void addToChallengeContext() {
    List<String> ctxList = new ArrayList<String>();
    extendedPublicKey.addToChallengeContext(ctxList);
    assertTrue(ctxList.size() > 0);
  }
}
