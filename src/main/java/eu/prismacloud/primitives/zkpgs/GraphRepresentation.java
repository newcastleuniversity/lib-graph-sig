package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.jgrapht.Graph;

/** The type Graph representation. */
public class GraphRepresentation {
  private static final Logger gslog = GSLoggerConfiguration.getGSlog();
  private final Map<URN, BaseRepresentation> bases;
  private final ExtendedPublicKey extendedPublicKey;
  private final GraphEncodingParameters encodingParameters;
  private Map<URN, BaseRepresentation> encodedBases = new LinkedHashMap<URN, BaseRepresentation>();
  private Map<URN, BaseRepresentation> excludedBases = new HashMap<URN, BaseRepresentation>();

  public GraphRepresentation(ExtendedPublicKey epk) {
    this.extendedPublicKey = epk;
    this.encodingParameters = epk.getGraphEncodingParameters();
    this.bases = epk.getBases();
  }

  /**
   * Encodes a graph structure created from a graphml file and associates a random base with the
   * vertex and edge encoding. Note that the random base for a vertex is selected uniformly from the
   * number of vertices and the random base for an edge is selected uniformly from the number of
   * edges.
   *
   * <p>The exponent of each vertex base is calculated by multiplying the vertex prime
   * representative with the list of the label representatives. Similarly, the exponent for each
   * edge base is computed by multiplying the vertex prime representatives that comprise the edge
   * and the label representatives of the edge.
   *
   * @param gsGraph the graph to encode
   * @return the encoded bases
   */
  public Map<URN, BaseRepresentation> encode(GSGraph<GSVertex, GSEdge> gsGraph) {
    Graph<GSVertex, GSEdge> graph;
    graph = gsGraph.getGraph();

    encodeVertices(graph);
    encodeEdges(graph);

    return bases;
  }

  private void encodeVertices(Graph<GSVertex, GSEdge> graph) {
    int baseIndex;
    Map<URN, BigInteger> vertexRepresentatives = extendedPublicKey.getVertexRepresentatives();
    Map<URN, BigInteger> labelRepresentatives = extendedPublicKey.getLabelRepresentatives();

    String label = "";
    Set<GSVertex> vertexSet = graph.vertexSet();
    for (GSVertex vertex : vertexSet) {
      BaseRepresentation base = extendedPublicKey.getRandomVertexBase(excludedBases);
      excludedBases.put(URN.createZkpgsURN("bases.vertex.R_i_" + base.getBaseIndex()), base);

      baseIndex = base.getBaseIndex();
      BigInteger vertexRepresentative =
          vertexRepresentatives.get(URN.createZkpgsURN("vertex.representative.e_i_" + baseIndex));
      Assert.notNull(vertexRepresentative, "cannot find vertex prime representative");

      vertex.setVertexRepresentative(vertexRepresentative);
      List<String> labels = vertex.getLabels();
      if (!labels.isEmpty()) {
        for (String lbl : labels) {
          if (!"".equals(lbl)) {
            label = lbl;
            break;
          }
        }
      }

      BigInteger labelRepresentative = labelRepresentatives.get(URN.createZkpgsURN(label));
      Assert.notNull(labelRepresentative, "cannot find label prime representative");

      List<BigInteger> vertexLabelRepresentatives = new ArrayList<>();

      vertexLabelRepresentatives.add(labelRepresentative);

      BigInteger exponentEncoding = encodeVertex(vertexRepresentative, vertexLabelRepresentatives);
      Assert.notNull(exponentEncoding, "Exponent encoding returned null.");

      Assert.notNull(base, "cannot find base index");

      base.setExponent(exponentEncoding);

      //      gslog.info("base index: " + base.getBaseIndex());
      //      gslog.info("vertex id " + vertex.getId());
      bases.replace(URN.createZkpgsURN("bases.vertex.R_" + base.getBaseIndex()), base);
    }
  }

  private void encodeEdges(Graph<GSVertex, GSEdge> graph) {

    Set<GSEdge> edgeSet = graph.edgeSet();

    for (GSEdge edge : edgeSet) {
      GSVertex e_i = edge.getE_i();
      GSVertex e_j = edge.getE_j();
      List<BigInteger> edgeLabels = edge.getLabelRepresentatives();

      Assert.notNull(edgeLabels, "Edge label set was found to be null.");
      Assert.notNull(e_i, "vertex edge was found to be null");
      Assert.notNull(e_j, "vertex edge was found to be null");

      BigInteger exponentEncoding =
          encodeEdge(e_i.getVertexRepresentative(), e_j.getVertexRepresentative(), edgeLabels);

      //      gslog.info("exponent encoding: " + exponentEncoding);
      Assert.notNull(exponentEncoding, "Edge label exponent was found to be null.");

      BaseRepresentation base = extendedPublicKey.getRandomEdgeBase(excludedBases);
      excludedBases.put(URN.createZkpgsURN("bases.edge.R_i_j_" + base.getBaseIndex()), base);

      Assert.notNull(base, "cannot find base index");

      base.setExponent(exponentEncoding);
      //      gslog.info("base index: " + base.getBaseIndex());
      //      gslog.info(
      //          "edge_i id: " + edge.getE_i().getId() + " edge_j id: " + edge.getE_j().getId() +
      // "\n");
      bases.replace(URN.createZkpgsURN("bases.edge.R_i_j_" + base.getBaseIndex()), base);
    }
  }

  /**
   * Return the encoded bases.
   *
   * @return the encoded bases
   */
  public Map<URN, BaseRepresentation> getEncodedBases() {
    return bases;
  }

  /**
   * Return encoded base collection.
   *
   * @return the encoded base collection
   */
  public BaseCollection getEncodedBaseCollection() {
    BaseCollectionImpl baseCollection = new BaseCollectionImpl();
    baseCollection.setBases(new ArrayList<BaseRepresentation>(bases.values()));
    return baseCollection;
  }

  /*
   * Encode a vertex with a vertex prime representative and a list of label prime representatives. The vertex prime representative is multiplied with the list of label prime representatives.
   */

  private BigInteger encodeVertex(
      BigInteger vertexPrimeRepresentative, List<BigInteger> labelRepresentatives) {

    Assert.notNull(vertexPrimeRepresentative, "vertex prime representative does not exist");
    Assert.notNull(labelRepresentatives, "labels prime representative does not exist");

    BigInteger e_k = BigInteger.ONE;
    if (labelRepresentatives != null) {
      for (BigInteger labelRepresentative : labelRepresentatives) {
        if (labelRepresentative != null) {
          e_k = e_k.multiply(labelRepresentative);
        }
      }
    }

    // TODO A vertex can have multiple labels, not just one.
    return vertexPrimeRepresentative.multiply(e_k);
  }

  /*
   * Encode an edge with the prime representatives of its vertices and a list of label prime representatives of the edge. The vertex prime representatives are multiplied with the list of label prime representatives.
   */

  // TODO An edge can have multiple labels, not just one.
  private BigInteger encodeEdge(
      BigInteger e_i, BigInteger e_j, List<BigInteger> labelRepresentatives) {

    Assert.notNull(e_i, "Vertex representative e_i was found null.");
    Assert.notNull(e_j, "Vertex representative e_j was found null.");

    BigInteger e_k = BigInteger.ONE;
    if (labelRepresentatives != null) {
      for (BigInteger labelRepresentative : labelRepresentatives) {
        if (labelRepresentative != null) {
          e_k = e_k.multiply(labelRepresentative);
        }
      }
    }

    return e_i.multiply(e_j.multiply(e_k));
  }
}
