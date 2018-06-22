package eu.prismacloud.primitives.zkpgs;

import static eu.prismacloud.primitives.zkpgs.GraphRepresentation.encode;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import java.io.File;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphImporter;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class GraphRepresentationTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  Graph<GSVertex, GSEdge> graph;

  Graph<GSVertex, GSEdge> graphi;
  GraphEncodingParameters graphEncodingParameters;
  ExtendedPublicKey extendedPublicKey;
  GSGraph<GSVertex, GSEdge> gsGraph;

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
    GraphRepresentation graphRepresentation =
        encode(gsGraph, graphEncodingParameters, extendedPublicKey);

    assertNotNull(graphRepresentation);
  }
}
