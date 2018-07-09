package eu.prismacloud.primitives.zkpgs.graph;

import eu.prismacloud.primitives.zkpgs.GraphMLProvider;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.io.File;
import java.math.BigInteger;
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

  public GSGraph(
      Graph<
              eu.prismacloud.primitives.zkpgs.graph.GSVertex,
              eu.prismacloud.primitives.zkpgs.graph.GSEdge>
          graph) {
    this.graph = graph;
  }

  public Graph<GSVertex, GSEdge> createGraph(String graphFile) throws ImportException {
    graph = new DefaultUndirectedGraph<>(eu.prismacloud.primitives.zkpgs.graph.GSEdge.class);

    importer = (GraphMLImporter<GSVertex, GSEdge>) GraphMLProvider.createImporter();
    File file = GraphMLProvider.getGraphMLFile(graphFile);
    importer.importGraph((Graph<GSVertex, GSEdge>) graph, file);

    return (Graph<GSVertex, GSEdge>) graph;
  }

  public void encodeGraph(
      Graph<GSVertex, GSEdge> graph, GraphEncodingParameters graphEncodingParameters) {
    JsonIsoCountries jsonIsoCountries = new JsonIsoCountries();

    Set<GSVertex> vertexSet = graph.vertexSet();

    for (GSVertex vertex : vertexSet) {
      //      gslog.log(Level.INFO, "vertex Id: " + vertex.getId());
      //      gslog.log(Level.INFO, "country: " + vertex.getCountry());
      vertex.setLabelPrimeRepresentative(
          BigInteger.valueOf(jsonIsoCountries.getIndex(vertex.getCountry())));
      //      gslog.log(Level.INFO, "label representative: " +
      // vertex.getLabelPrimeRepresentative());
      BigInteger vertexPrimeRepresentative =
          CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_L());
      vertex.setVertexPrimeRepresentative(vertexPrimeRepresentative);
//      gslog.log(
//          Level.INFO, "vertex prime representative: " + vertex.getVertexPrimeRepresentative());
    }
  }

  public Graph<
          eu.prismacloud.primitives.zkpgs.graph.GSVertex,
          eu.prismacloud.primitives.zkpgs.graph.GSEdge>
      getGraph() {
    return graph;
  }
}
