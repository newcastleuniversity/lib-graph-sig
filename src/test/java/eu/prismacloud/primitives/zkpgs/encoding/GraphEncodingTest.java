package eu.prismacloud.primitives.zkpgs.encoding;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRGroupN;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GraphEncodingTest {
  private KeyGenParameters keygenParams;
  private Map<URN, BaseRepresentation> bases;
  private BigInteger vertexRepresentative;
  private Map<URN, BigInteger> vertexRepresentatives;
  private SignerKeyPair gsk;
  private SignerPublicKey signerPublicKey;
  private GraphEncodingParameters graphEncodingParameters;
  private KeyGenParameters keyGenParameters;
  private ExtendedKeyPair extendedKeyPair;
  private GraphEncoding graphEncoding;

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

    BaseRepresentation base =
        new BaseRepresentation(
            new QRElement(new QRGroupN(BigInteger.valueOf(4)), new BigInteger("2")),
            1,
            BASE.VERTEX);

    bases = new HashMap<URN, BaseRepresentation>();

    bases.put(URN.createZkpgsURN("test.base"), base);

    vertexRepresentative = BigInteger.valueOf(13);

    vertexRepresentatives = new HashMap<URN, BigInteger>();
    vertexRepresentatives.put(
        URN.createZkpgsURN("test.vertex.representative"), vertexRepresentative);

    graphEncoding =
        new GraphEncoding(
            bases,
            vertexRepresentatives,
            signerPublicKey,
            keyGenParameters,
            graphEncodingParameters);
  }

  @Test
  void testCreatingGraphEncoding() {
    GraphEncoding graphEncoding =
        new GraphEncoding(
            bases,
            vertexRepresentatives,
            signerPublicKey,
            keyGenParameters,
            graphEncodingParameters);

    assertNotNull(graphEncoding);
  }

  @Test
  void setupGraphEncoding() {}

  @Test
  void getBases() {
    Map<URN, BaseRepresentation> bases = graphEncoding.getBases();
    assertNotNull(bases);
    assertTrue(bases.size() > 0);
  }

  @Test
  void getVertexPrimeRepresentatives() {

    Map<URN, BigInteger> vertexPrimeRepresentatives = graphEncoding.getVertexPrimeRepresentatives();
    assertNotNull(vertexPrimeRepresentatives);
    assertTrue(vertexPrimeRepresentatives.size() > 0);
  }
}
