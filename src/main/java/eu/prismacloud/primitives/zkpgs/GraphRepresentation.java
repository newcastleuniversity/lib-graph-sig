package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.Graph;

/** The type Graph representation. */
public class GraphRepresentation {
  private static Logger gslog = GSLoggerConfiguration.getGSlog();
  private static List<Integer> crossoutBaseIndex;
  private static Map<URN, BaseRepresentation> bases;
  private ExtendedPublicKey extendedPublicKey;
  private static GraphEncodingParameters encodingParameters;

  private GraphRepresentation(Map<URN, BaseRepresentation> bases) {
    this.bases = bases;
  }

  /**
   * Encode graph representation.
   *
   * @param gsGraph the graph to encode
   * @param graphEncodingParameters the graph encoding parameters
   * @param extendedPublicKey the extended public key
   * @return the graph representation
   */
  public static GraphRepresentation encode(
      GSGraph<GSVertex, GSEdge> gsGraph,
      GraphEncodingParameters graphEncodingParameters,
      ExtendedPublicKey extendedPublicKey) {
    Graph<GSVertex, GSEdge> graph;

    encodingParameters = graphEncodingParameters;

    graph = gsGraph.getGraph();

    bases = extendedPublicKey.getBases();

    crossoutBaseIndex = new ArrayList<Integer>();

    encodeVertices(graph, bases);

    encodeEdges(graph, bases);

    return new GraphRepresentation(bases);
  }

  private static void encodeEdges(
      Graph<GSVertex, GSEdge> graph, Map<URN, BaseRepresentation> bases) {
    String labelRepresentative;
    GSVertex e_i;
    GSVertex e_j;
    BigInteger exponentEncoding;
    Set<GSEdge> edgeSet = graph.edgeSet();

    for (GSEdge edge : edgeSet) {
      e_i = edge.getE_i();
      gslog.log(Level.INFO, "vertex e_i : " + e_i);
      gslog.log(Level.INFO, "vertex e_i id : " + e_i.getId());

      labelRepresentative = edge.getLabelRepresentative();
      gslog.log(Level.INFO, "label representative: " + labelRepresentative);

      e_j = edge.getE_j();
      gslog.log(Level.INFO, "vertex e_j: " + e_j);
      gslog.log(Level.INFO, "vertex e_i id: " + e_j.getId());

      exponentEncoding =
          encodeEdge(
              e_i.getVertexPrimeRepresentative(),
              e_j.getVertexPrimeRepresentative(),
              new BigInteger(labelRepresentative));

      gslog.log(Level.INFO, "edge exponentEncoding: " + exponentEncoding);

      BaseRepresentation base = generateRandomBase();
      Assert.notNull(base, "cannot find base index");

      gslog.log(Level.INFO, "random base : " + base);

      base.setExponent(exponentEncoding);

      bases.put(URN.createZkpgsURN("bases.edge.R_i_j_" + base.getBaseIndex()), base);
    }
  }

  private static void encodeVertices(
      Graph<GSVertex, GSEdge> graph, Map<URN, BaseRepresentation> bases) {
    BigInteger labelRepresentative;
    BigInteger vertexRepresentative;
    BigInteger exponentEncoding;
    Set<GSVertex> vertexSet = graph.vertexSet();

    for (GSVertex vertex : vertexSet) {
      gslog.log(Level.INFO, "vertex Id: " + vertex.getId());
      gslog.log(Level.INFO, "country: " + vertex.getCountry());

      labelRepresentative = vertex.getLabelPrimeRepresentative();
      gslog.log(Level.INFO, "label representative: " + labelRepresentative);

      vertexRepresentative = vertex.getVertexPrimeRepresentative();
      gslog.log(Level.INFO, "vertex prime representative: " + vertexRepresentative);

      exponentEncoding = encodeVertex(vertexRepresentative, labelRepresentative);
      gslog.log(Level.INFO, "exponentEncoding: " + exponentEncoding);

      BaseRepresentation base = generateRandomBase();
      Assert.notNull(base, "cannot find base index");

      base.setExponent(exponentEncoding);
      bases.put(URN.createZkpgsURN("bases.vertex.R_" + base.getBaseIndex()), base);
    }
  }

  private static BaseRepresentation generateRandomBase() {
    int randomBaseIndex =
        CryptoUtilsFacade.computeRandomNumber(BigInteger.ONE, BigInteger.valueOf(bases.size()))
            .intValue();
    List<Integer> crossoutBaseIndex = new ArrayList<Integer>();

    for (BaseRepresentation baseRepresentation : bases.values()) {
      if (baseRepresentation.getBaseIndex() == randomBaseIndex) {
        if (crossoutBaseIndex.get(randomBaseIndex) == null) {
          crossoutBaseIndex.add(randomBaseIndex);
          return baseRepresentation;
        }
      }
    }
    return null;
  }

  /**
   * Gets encoded bases.
   *
   * @return the encoded bases
   */
  public static Map<URN, BaseRepresentation> getEncodedBases() {
    return bases;
  }

  private static BigInteger encodeVertex(
      BigInteger vertexPrimeRepresentative, BigInteger labelPrimeRepresentative) {

    return vertexPrimeRepresentative.multiply(labelPrimeRepresentative);
  }

  private static BigInteger encodeEdge(BigInteger e_i, BigInteger e_j, BigInteger e_k) {

    return e_i.multiply(e_j.multiply(e_k));
  }
}
