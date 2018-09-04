package eu.prismacloud.primitives.zkpgs.graph;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import eu.prismacloud.primitives.zkpgs.encoding.GeoLocationGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
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
  void setUp() throws ImportException, EncodingException {
    GraphEncodingParameters graphEncodingParameters =
        new GraphEncodingParameters(1000, 120, 50000, 256, 16);
    GeoLocationGraphEncoding encoding = new GeoLocationGraphEncoding(graphEncodingParameters);
    encoding.setupEncoding();

    GSGraph<GSVertex, GSEdge> gsgraph = GSGraph.createGraph(SIGNER_GRAPH_FILE);
    assertNotNull(gsgraph);
    assertNotNull(gsgraph.getGraph());

    gsgraph.encodeGraph(encoding);
    vertices = gsgraph.getGraph().vertexSet();
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
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    labels.add("UK");
    vertex.setLabels(labels);

    assertNotNull(vertex.getLabels());
    assertEquals("UK", vertex.getLabels().get(0));
  }

  @Test
  void getId() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);

    assertNotNull(vertex.getId());
    assertEquals("1", vertex.getId());
  }

  @Test
  void setId() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);

    assertNotNull(vertex.getId());
    vertex.setId("2");
    assertEquals("2", vertex.getId());
  }

  @Test
  void getLabelPrimeRepresentatives() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(1259));
    vertex.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(vertex.getLabelRepresentatives());
    assertEquals(1, vertex.getLabelRepresentatives().size());
  }

  @Test
  void setLabelPrimeRepresentatives() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    ArrayList<BigInteger> labelRepresentatives = new ArrayList<>();
    labelRepresentatives.add(BigInteger.valueOf(2389));
    vertex.setLabelRepresentatives(labelRepresentatives);
    assertNotNull(vertex.getLabelRepresentatives());
    assertEquals(BigInteger.valueOf(2389), vertex.getLabelRepresentatives().get(0));
  }

  @Test
  void getVertexPrimeRepresentative() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    vertex.setVertexRepresentative(BigInteger.valueOf(3061));
    assertNotNull(vertex.getVertexRepresentative());
    assertEquals(BigInteger.valueOf(3061), vertex.getVertexRepresentative());
  }

  @Test
  void setVertexPrimeRepresentative() {
    ArrayList<String> labels = new ArrayList<>();
    GSVertex vertex = new GSVertex("1", labels);
    vertex.setVertexRepresentative(BigInteger.valueOf(5351));
    assertNotNull(vertex.getVertexRepresentative());
    assertEquals(BigInteger.valueOf(5351), vertex.getVertexRepresentative());
  }
}
