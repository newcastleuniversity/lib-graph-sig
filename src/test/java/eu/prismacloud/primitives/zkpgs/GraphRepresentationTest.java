package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertNotNull;

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

  @BeforeEach
  void setUp() throws ImportException {

    File file = GraphMLProvider.getGraphMLFile(SIGNER_GRAPH_FILE);
    assertNotNull(file);

    graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);
    GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
    assertNotNull(importer);

    importer.importGraph(graph, file);
    assertNotNull(graph);

    graphEncodingParameters = new GraphEncodingParameters(1000, 120, 50000, 256, 16);
    gsGraph = new GSGraph<>(graph);

    graphi = gsGraph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(gsGraph);

    gsGraph.encodeGraph(graphi, graphEncodingParameters);
  }

  @Test
  void encodeGraph() {
    /** TODO fix test for graph representation */
    GraphRepresentation graphRepresentation = new GraphRepresentation();

    graphRepresentation.encode(gsGraph, graphEncodingParameters, extendedPublicKey);

    assertNotNull(graphRepresentation);
  }
}
