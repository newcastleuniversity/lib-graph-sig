package eu.prismacloud.primitives.zkpgs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.File;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphImporter;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/** */
class GraphMLProviderTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  @BeforeEach
  void setUp() {}

  @Test
  void getGraphMLFile() {
    File file = GraphMLProvider.getGraphMLFile(SIGNER_GRAPH_FILE);
    assertNotNull(file);
  }

  @Test
  @RepeatedTest(10)
  void createImporter() throws ImportException {

    Graph<GSVertex, GSEdge> graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
    assertNotNull(importer);
    File file = GraphMLProvider.getGraphMLFile(SIGNER_GRAPH_FILE);
    assertNotNull(file);

    importer.importGraph(graph, file);

    assertNotNull(graph);
    assertTrue(!graph.vertexSet().isEmpty());
    assertTrue(!graph.edgeSet().isEmpty());
    gslog.info("vertex size: " + graph.vertexSet().size());
    gslog.info("edge size: " + graph.edgeSet().size());
    assertEquals(15, graph.vertexSet().size());
    assertEquals(14, graph.edgeSet().size());
  }
}
