package eu.prismacloud.primitives.zkpgs;

import static eu.prismacloud.primitives.zkpgs.GraphRepresentation.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.util.Map;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class GraphRepresentationTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  GSGraph<GSVertex, GSEdge> graph;
  GraphEncodingParameters graphEncodingParameters;
  ExtendedPublicKey extendedPublicKey;

  @BeforeEach
  void setUp() throws ImportException {

    Graph<GSVertex, GSEdge> g =
        new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);
    Graph<GSVertex, GSEdge> gsGraph;

    graphEncodingParameters = new GraphEncodingParameters(1000, 120, 50000, 256, 16);

    //    graph = new GSGraph<GSVertex, GSEdge>(g);

    gsGraph = graph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(gsGraph);

    graph.encodeGraph(gsGraph, graphEncodingParameters);
  }

  @Test
  void encodeGraph() {

    GraphRepresentation graphRepresentation =
        encode(graph, graphEncodingParameters, extendedPublicKey);

    assertNotNull(graphRepresentation);
  }
}
