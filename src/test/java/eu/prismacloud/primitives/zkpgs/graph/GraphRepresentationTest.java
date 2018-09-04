package eu.prismacloud.primitives.zkpgs.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseTest;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GraphRepresentationTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  DefaultUndirectedGraph<GSVertex, GSEdge> graph;

  Graph<GSVertex, GSEdge> graphi;
  GraphEncodingParameters graphEncodingParameters;
  ExtendedPublicKey extendedPublicKey;
  GSGraph<GSVertex, GSEdge> gsGraph;
  private KeyGenParameters keyGenParameters;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, EncodingException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
  }

  @BeforeEach
  void setUp() throws ImportException, EncodingException {
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();

    gsGraph = GSGraph.createGraph(SIGNER_GRAPH_FILE);
  }

  @Test
  void encodeGraph() {
    GraphRepresentation graphRepresentation = new GraphRepresentation(extendedPublicKey);

    Map<URN, BaseRepresentation> encodedBases = graphRepresentation.encode(gsGraph);
    int numberOfBases = graphEncodingParameters.getL_V() + graphEncodingParameters.getL_E();
    assertNotNull(graphRepresentation);
    assertNotNull(encodedBases);
    assertEquals(numberOfBases, encodedBases.size());
    assertNotNull(graphRepresentation.getEncodedBaseCollection());
    assertEquals(numberOfBases, graphRepresentation.getEncodedBaseCollection().size());
    assertNotNull(graphRepresentation.getEncodedBases());
    assertEquals(numberOfBases, graphRepresentation.getEncodedBases().size());
  }

  @Test
//  @RepeatedTest(10)
  void testBaseCollection() {
    GraphRepresentation graphRepresentation = new GraphRepresentation(extendedPublicKey);

    Map<URN, BaseRepresentation> encodedBases = graphRepresentation.encode(gsGraph);
    assertNotNull(encodedBases);
    gslog.info("encoded bases: " + encodedBases.size());
    int numberOfBases = graphEncodingParameters.getL_V() + graphEncodingParameters.getL_E();
    assertNotNull(graphRepresentation);

    BaseCollection baseCollection = graphRepresentation.getEncodedBaseCollection();

    assertEquals(numberOfBases, baseCollection.size());

    // create an iterator that includes only the bases with an exponent
    BaseIterator baseIterator = baseCollection.createIterator(BASE.ALL);
    for (BaseRepresentation baseRepresentation : baseIterator) {

      assertNotNull(baseRepresentation.getExponent());

      gslog.info(
          "baseType: "
              + baseRepresentation.getBaseType()
              + " base: "
              + baseRepresentation.getBaseIndex()
              + " baseExponent: "
              + baseRepresentation.getExponent()
              + "\n");
    }

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    gslog.info("------ vertices: \n");
    gslog.info("vertices size: " + vertexIterator.size() + "\n");
    for (BaseRepresentation vertexRep : vertexIterator) {

      gslog.info(
          "baseType: "
              + vertexRep.getBaseType()
              + " base: "
              + vertexRep.getBaseIndex()
              + " baseExponent: "
              + vertexRep.getExponent()
              + "\n");
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    gslog.info("----- edges: \n");
    gslog.info("edges size: " + edgeIterator.size() + "\n");
    for (BaseRepresentation edgeRep : edgeIterator) {

      gslog.info(
          "baseType: "
              + edgeRep.getBaseType()
              + " base: "
              + edgeRep.getBaseIndex()
              + " baseExponent: "
              + edgeRep.getExponent()
              + "\n");
    }

    int vertexSize = gsGraph.getGraph().vertexSet().size();
    int edgeSize = gsGraph.getGraph().edgeSet().size();

    gslog.info("graph vertex size: " + vertexSize);
    gslog.info("graph edge size: " + edgeSize);

    assertEquals(vertexSize + edgeSize, baseIterator.size());
  }
}
