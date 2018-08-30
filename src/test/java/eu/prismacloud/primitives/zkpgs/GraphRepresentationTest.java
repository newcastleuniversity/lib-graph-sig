package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphImporter;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

/** */
@TestInstance(Lifecycle.PER_CLASS)
class GraphRepresentationTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  Graph<GSVertex, GSEdge> graph;

  Graph<GSVertex, GSEdge> graphi;
  GraphEncodingParameters graphEncodingParameters;
  ExtendedPublicKey extendedPublicKey;
  GSGraph<GSVertex, GSEdge> gsGraph;
  private KeyGenParameters keyGenParameters;
  private Logger log = GSLoggerConfiguration.getGSlog();
  private SignerKeyPair gsk;
  private ExtendedKeyPair extendedKeyPair;

  @BeforeAll
  void setupKey() throws IOException, ClassNotFoundException, EncodingException {
    BaseTest baseTest = new BaseTest();
    baseTest.setup();
    baseTest.shouldCreateASignerKeyPair(BaseTest.MODULUS_BIT_LENGTH);
    gsk = baseTest.getSignerKeyPair();
    graphEncodingParameters = baseTest.getGraphEncodingParameters();
    keyGenParameters = baseTest.getKeyGenParameters();
    extendedKeyPair = new ExtendedKeyPair(gsk, graphEncodingParameters, keyGenParameters);
    extendedKeyPair.generateBases();
    extendedKeyPair.setupEncoding();
    extendedKeyPair.createExtendedKeyPair();
    extendedPublicKey = extendedKeyPair.getExtendedPublicKey();
  }

  @BeforeEach
  void setUp() throws ImportException {
    File file = GraphMLProvider.getGraphMLFile(SIGNER_GRAPH_FILE);
    graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);
    GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
    importer.importGraph(graph, file);
    graphEncodingParameters = new GraphEncodingParameters(100, 120, 500, 256, 16);
    gsGraph = new GSGraph<>(graph);
    graphi = gsGraph.createGraph(SIGNER_GRAPH_FILE);
  }

  @Test
  void encodeGraph() {
    GraphRepresentation graphRepresentation = new GraphRepresentation(extendedPublicKey);

    graphRepresentation.encode(gsGraph);

    assertNotNull(graphRepresentation);
    assertNotNull(graphRepresentation.getEncodedBases());
    assertEquals(600, graphRepresentation.getEncodedBases().size());
  }
}
