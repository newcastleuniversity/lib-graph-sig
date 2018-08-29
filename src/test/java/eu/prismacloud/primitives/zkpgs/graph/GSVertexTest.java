package eu.prismacloud.primitives.zkpgs.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** */
class GSVertexTest {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private Set<GSEdge> edges;
  private Set<GSVertex> vertices;
  private GSEdge edge;
  private GSVertex vertex;

  @BeforeEach
  void setUp() throws ImportException {
    Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GraphEncodingParameters graphEncodingParameters =
        new GraphEncodingParameters(1000, 120, 50000, 256, 16);

    GSGraph<GSVertex, GSEdge> graph = new GSGraph<GSVertex, GSEdge>(g);

    g = graph.createGraph(SIGNER_GRAPH_FILE);

    graph.encodeRandomGeoLocationGraph(graphEncodingParameters);
    vertices = g.vertexSet();
  }

  @Test
  void getLabels() {
    vertex = vertices.iterator().next();
    assertNotNull(vertex.getLabels());
    assertFalse(vertex.getLabels().isEmpty());
    assertNotNull(vertex.getLabels().iterator().next());
  }

  @Test
  void setLabels() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    labels.add("UK");
    vertex.setLabels(labels);

    assertNotNull(vertex.getLabels());
    assertEquals("UK", vertex.getLabels().get(0));
  }

  @Test
  void getId() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);

    assertNotNull(vertex.getId());
    assertEquals("1", vertex.getId());
  }

  @Test
  void setId() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);

    assertNotNull(vertex.getId());
    vertex.setId("2");
    assertEquals("2", vertex.getId());
  }

  @Test
  void getLabelPrimeRepresentatives() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    List<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(1259));
    vertex.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(vertex.getLabelPrimeRepresentatives());
    assertEquals(1, vertex.getLabelPrimeRepresentatives().size());
  }

  @Test
  void setLabelPrimeRepresentatives() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    List<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(2389));
    vertex.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(vertex.getLabelPrimeRepresentatives());
    assertEquals(BigInteger.valueOf(2389), vertex.getLabelPrimeRepresentatives().get(0));
  }

  @Test
  void getVertexPrimeRepresentative() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    vertex.setVertexRepresentative(BigInteger.valueOf(3061));
    assertNotNull(vertex.getVertexRepresentative());
    assertEquals(BigInteger.valueOf(3061), vertex.getVertexRepresentative());
  }

  @Test
  void setVertexPrimeRepresentative() {
    List<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    vertex.setVertexRepresentative(BigInteger.valueOf(5351));
    assertNotNull(vertex.getVertexRepresentative());
    assertEquals(BigInteger.valueOf(5351), vertex.getVertexRepresentative());
  }
}
