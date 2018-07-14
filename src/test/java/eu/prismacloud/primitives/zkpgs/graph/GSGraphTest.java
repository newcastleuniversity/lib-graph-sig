package eu.prismacloud.primitives.zkpgs.graph;

import static org.junit.Assert.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.Test;

/** Test graphs */
class GSGraphTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";


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

    graph.encodeGraph(graphEncodingParameters);
    Set<GSEdge> edges = g.edgeSet();
    Set<GSVertex> vertices = g.vertexSet();

    assertFalse(edges.isEmpty());
    assertFalse(vertices.isEmpty());

    for (GSVertex vertex : vertices) {
      assertNotNull(vertex.getLabels());
      assertNotNull(vertex.getVertexPrimeRepresentative());
      assertTrue(vertex.getVertexPrimeRepresentative().isProbablePrime(80));
      
    }

    for (GSEdge edge : edges) {
      assertNotNull(edge.getE_i());
      assertNotNull(edge.getE_j());
      assertTrue(edge.getE_i().getVertexPrimeRepresentative().isProbablePrime(80));
      assertTrue(edge.getE_j().getVertexPrimeRepresentative().isProbablePrime(80));
    }
  }

}
