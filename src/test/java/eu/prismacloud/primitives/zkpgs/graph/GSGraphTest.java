package eu.prismacloud.primitives.zkpgs.graph;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Test graphs */
class GSGraphTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";

  @BeforeEach
  void setUp() {}

  @Test
  void createGraph() throws ImportException {
    Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GSGraph<GSVertex, GSEdge> graph = new GSGraph<GSVertex, GSEdge>(g);

    g = graph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(g);
  }

  @Test
  void encodeGraph() throws ImportException {
    Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GraphEncodingParameters graphEncodingParameters =
        new GraphEncodingParameters(1000, 120, 50000, 256, 16);

    GSGraph<GSVertex, GSEdge> graph = new GSGraph<GSVertex, GSEdge>(g);

    g = graph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(g);

    graph.encodeGraph(g, graphEncodingParameters);
  }

  @Test
  void addConnectingVertex() {}
}
