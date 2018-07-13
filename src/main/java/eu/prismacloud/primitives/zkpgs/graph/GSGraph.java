package eu.prismacloud.primitives.zkpgs.graph;

import eu.prismacloud.primitives.zkpgs.GraphMLProvider;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.graph.SimpleGraph;
import org.jgrapht.io.GraphMLImporter;
import org.jgrapht.io.ImportException;

public class GSGraph<
    GSVertex extends eu.prismacloud.primitives.zkpgs.graph.GSVertex,
    GSEdge extends eu.prismacloud.primitives.zkpgs.graph.GSEdge> {
  private static Logger gslog = GSLoggerConfiguration.getGSlog();
  private static GraphMLProvider graphMLProvider;
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private static final String RECIPIENT_GRAPH_FILE = "recipient-infra.graphml";
  /** The Graph. */
  Graph<
          eu.prismacloud.primitives.zkpgs.graph.GSVertex,
          eu.prismacloud.primitives.zkpgs.graph.GSEdge>
      graph;

  private SimpleGraph<GSVertex, GSEdge> g;
  private GraphMLImporter<GSVertex, GSEdge> importer;

  /**
   * Creates a new GSGraph with the corresponding vertices and edges after parsing a graphml file.
   *
   * @param graph the graph
   */
  public GSGraph(
        Graph<
              eu.prismacloud.primitives.zkpgs.graph.GSVertex,
              eu.prismacloud.primitives.zkpgs.graph.GSEdge>
          graph) {
    this.graph = graph;
  }

  /**
   * Creates a graph structure with a number of vertices and edges after importing the graphml file.
   *
   * @param graphFile the graph file
   * @return the graph
   * @throws ImportException the import exception
   */
  public Graph<GSVertex, GSEdge> createGraph(String graphFile) throws ImportException {
    graph = new DefaultUndirectedGraph<>(eu.prismacloud.primitives.zkpgs.graph.GSEdge.class);

    importer = (GraphMLImporter<GSVertex, GSEdge>) GraphMLProvider.createImporter();
    File file = GraphMLProvider.getGraphMLFile(graphFile);
    importer.importGraph((Graph<GSVertex, GSEdge>) graph, file);

    return (Graph<GSVertex, GSEdge>) graph;
  }

  /**
   * Encodes a graph that has been constructed from an imported graphml file. Selects the vertex
   * prime representative for a vertex and its prime representatives for the labels. The edge prime
   * representative is selected and its prime representatives for the labels.
   *
   * @param graph the graph which includes the vertices, edges and associated labels
   * @param graphEncodingParameters the graph encoding parameters
   */
  public void encodeGraph(
      Graph<GSVertex, GSEdge> graph, GraphEncodingParameters graphEncodingParameters) {
    JsonIsoCountries jsonIsoCountries = new JsonIsoCountries();
    BigInteger vertexPrimeRepresentative;

    Set<GSVertex> vertexSet = graph.vertexSet();
    List<BigInteger> labelRepresentatives = new ArrayList<>();

    for (GSVertex vertex : vertexSet) {

      if ((vertex.getLabels() != null) && (!vertex.getLabels().isEmpty())) {
        for (String label : vertex.getLabels()) {
          labelRepresentatives.add(BigInteger.valueOf(jsonIsoCountries.getIndex(label)));
        }
      }
      vertex.setLabelPrimeRepresentatives(labelRepresentatives);
      vertexPrimeRepresentative =
          CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_L());
      vertex.setVertexPrimeRepresentative(vertexPrimeRepresentative);
    }

    Set<GSEdge> edgeSet = graph.edgeSet();
    
    for (GSEdge edge : edgeSet) {

      if ((edge.getLabels() != null) && (!edge.getLabels().isEmpty())) {
        for (String label : edge.getLabels()) {
          labelRepresentatives.add(BigInteger.valueOf(jsonIsoCountries.getIndex(label)));
        }
        edge.setLabelRepresentatives(labelRepresentatives);
      }
    }
  }

  /**
   * Returns a graph.
   *
   * @return the graph
   */
  public Graph<
          eu.prismacloud.primitives.zkpgs.graph.GSVertex,
          eu.prismacloud.primitives.zkpgs.graph.GSEdge>
      getGraph() {
    return graph;
  }
}
