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

    GSGraph<GSVertex, GSEdge> gsgraph = GSGraph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(gsgraph);
    assertNotNull(gsgraph.getGraph());
  }

  @Test
  void encodeGraph() throws ImportException {
    GraphEncodingParameters graphEncodingParameters =
        new GraphEncodingParameters(1000, 120, 50000, 256, 16);

    GSGraph<GSVertex, GSEdge> gsgraph = GSGraph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(gsgraph);
    assertNotNull(gsgraph.getGraph());

    gsgraph.encodeRandomGeoLocationGraph(graphEncodingParameters);
    Set<GSEdge> edges = gsgraph.getGraph().edgeSet();
    Set<GSVertex> vertices = gsgraph.getGraph().vertexSet();

    assertFalse(edges.isEmpty());
    assertFalse(vertices.isEmpty());

    for (GSVertex vertex : vertices) {
      assertNotNull(vertex.getLabels());
      assertNotNull(vertex.getVertexRepresentative());
      assertTrue(vertex.getVertexRepresentative().isProbablePrime(80));
      
    }

    for (GSEdge edge : edges) {
      assertNotNull(edge.getE_i());
      assertNotNull(edge.getE_j());
      assertTrue(edge.getE_i().getVertexRepresentative().isProbablePrime(80));
      assertTrue(edge.getE_j().getVertexRepresentative().isProbablePrime(80));
    }
  }

}
