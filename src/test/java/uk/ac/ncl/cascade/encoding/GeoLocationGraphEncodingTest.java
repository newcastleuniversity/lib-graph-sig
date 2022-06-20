package uk.ac.ncl.cascade.encoding;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import uk.ac.ncl.cascade.BaseTest;
import uk.ac.ncl.cascade.zkpgs.encoding.GeoLocationGraphEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class GeoLocationGraphEncodingTest {
  private SignerKeyPair gsk;
  private SignerPublicKey signerPublicKey;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private GeoLocationGraphEncoding graphEncoding;

  @BeforeEach
  void setUp() throws IOException, ClassNotFoundException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    signerPublicKey = gsk.getPublicKey();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);

    graphEncoding =
        new GeoLocationGraphEncoding(graphEncodingParameters);
  }

  @Test
  @DisplayName("Test creating geolocation graph encoding")
  void testCreatingGraphEncoding() {
    GeoLocationGraphEncoding graphEncoding =
        new GeoLocationGraphEncoding(graphEncodingParameters);

    assertNotNull(graphEncoding);
  }

  @Test
  @DisplayName(
      "Test geolocation graph encoding setup creates vertex and label representatives maps")
  void setupGraphEncodingSetup() throws EncodingException {
    graphEncoding.setupEncoding();
    assertNotNull(graphEncoding.getVertexRepresentatives());
    assertTrue(!graphEncoding.getVertexRepresentatives().isEmpty());

    assertNotNull(graphEncoding.getLabelRepresentatives());
    assertNotNull(!graphEncoding.getLabelRepresentatives().isEmpty());
  }

  @Test
  @DisplayName("Test geolocation graph encoding returns vertex prime representative")
  void testReturnVertexRepresentative() throws EncodingException {
    graphEncoding.setupEncoding();
    assertNotNull(graphEncoding.getVertexRepresentatives());
    assertTrue(!graphEncoding.getVertexRepresentatives().isEmpty());

    Map<URN, BigInteger> testVertexRepresentatives = graphEncoding.getVertexRepresentatives();
    BigInteger testVertexRepresentative =
        testVertexRepresentatives.get(URN.createZkpgsURN("vertex.representative.e_i_0"));
    assertNotNull(testVertexRepresentative);
    assertTrue(testVertexRepresentative.isProbablePrime(80));
  }

  @Test
  @DisplayName(
      "Test geolocation graph encoding returns corresponding country label prime representative")
  void testReturnLabelRepresentative() throws EncodingException {
    graphEncoding.setupEncoding();
    assertNotNull(graphEncoding.getLabelRepresentatives());
    assertTrue(!graphEncoding.getLabelRepresentatives().isEmpty());

    Map<URN, BigInteger> testLabelRepresentatives = graphEncoding.getLabelRepresentatives();

    // country Andorra
    BigInteger testLabelRepresentative = testLabelRepresentatives.get(URN.createUnsafeZkpgsURN("AD"));
    assertNotNull(testLabelRepresentative);
    assertEquals(BigInteger.valueOf(2), testLabelRepresentative);
    assertTrue(testLabelRepresentative.isProbablePrime(80));

    // country Wallis and Futuna
    testLabelRepresentative = testLabelRepresentatives.get(URN.createUnsafeZkpgsURN("WF"));
    assertNotNull(testLabelRepresentative);
    assertEquals(BigInteger.valueOf(1543), testLabelRepresentative);
    assertTrue(testLabelRepresentative.isProbablePrime(80));
  }

  @Test
  @DisplayName("Test geolocation graph encoding returns vertex prime representatives maps")
  void getVertexPrimeRepresentatives() throws EncodingException {
    graphEncoding.setupEncoding();
    Map<URN, BigInteger> vertexPrimeRepresentatives = graphEncoding.getVertexRepresentatives();
    assertNotNull(vertexPrimeRepresentatives);
    assertTrue(vertexPrimeRepresentatives.size() > 0);

    for (BigInteger vertexPrimeRepresentative : vertexPrimeRepresentatives.values()) {
      assertTrue(vertexPrimeRepresentative.isProbablePrime(80));
    }
  }

  @Test
  @DisplayName(
      "Test geolocation graph encoding returns label prime representatives with  the required number of countries")
  void getLabelRepresentatives() throws EncodingException {
    graphEncoding.setupEncoding();
    Map<URN, BigInteger> testLabelRepresentatives = graphEncoding.getLabelRepresentatives();
    assertNotNull(testLabelRepresentatives);
    assertTrue(!testLabelRepresentatives.isEmpty());
    int numberOfCountries = 249;
    assertEquals(numberOfCountries, testLabelRepresentatives.size());

    for (BigInteger labelPrimeRepresentative : testLabelRepresentatives.values()) {
      assertTrue(labelPrimeRepresentative.isProbablePrime(80));
      assertTrue(
          CryptoUtilsFacade.isInRange(
              labelPrimeRepresentative,
              graphEncodingParameters.getLeastLabelRepresentative(),
              graphEncodingParameters.getUpperBoundLabelRepresentatives()));
    }
  }
}
