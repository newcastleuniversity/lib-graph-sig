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
   * @param graphEncodingParameters the graph encoding parameters
   */
  public void encodeGraph(GraphEncodingParameters graphEncodingParameters) {
    JsonIsoCountries jsonIsoCountries = new JsonIsoCountries();
    BigInteger vertexPrimeRepresentative;
    BigInteger labelPrimeRepresentative;

    Set<eu.prismacloud.primitives.zkpgs.graph.GSVertex> vertexSet = this.graph.vertexSet();
    List<BigInteger> vertexLabelRepresentatives = new ArrayList<>();
    List<BigInteger> edgeLabelRepresentatives = new ArrayList<>();

    for (eu.prismacloud.primitives.zkpgs.graph.GSVertex vertex : vertexSet) {
      vertexLabelRepresentatives = new ArrayList<>();

      if ((vertex.getLabels() != null) && (!vertex.getLabels().isEmpty())) {
        for (String label : vertex.getLabels()) {
          labelPrimeRepresentative = jsonIsoCountries.getCountryPrime(label);
          vertexLabelRepresentatives.add(labelPrimeRepresentative);
        }
      }

      vertexPrimeRepresentative =
          CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_L());
      vertex.setVertexPrimeRepresentative(vertexPrimeRepresentative);
      vertex.setLabelPrimeRepresentatives(vertexLabelRepresentatives);
    }

    Set<eu.prismacloud.primitives.zkpgs.graph.GSEdge> edgeSet = graph.edgeSet();

    for (eu.prismacloud.primitives.zkpgs.graph.GSEdge edge : edgeSet) {

      if ((edge.getLabels() != null) && (!edge.getLabels().isEmpty())) {
        for (String label : edge.getLabels()) {
          labelPrimeRepresentative = jsonIsoCountries.getCountryPrime(label);
          edgeLabelRepresentatives.add(labelPrimeRepresentative);
        }
        edge.setLabelRepresentatives(edgeLabelRepresentatives);
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
