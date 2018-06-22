package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import java.io.File;
import org.jgrapht.io.EdgeProvider;
import org.jgrapht.io.GraphMLImporter;
import org.jgrapht.io.VertexProvider;

/** Imports a graphml file with the graph structure of the cloud infrastructure. */
public class GraphMLProvider {

  private GraphMLProvider() {}

  public static File getGraphMLFile(String graphFile) {
    ClassLoader classLoader = GraphMLProvider.class.getClassLoader();
    return new File(classLoader.getResource(graphFile).getFile());
  }

  public static GraphMLImporter<GSVertex, GSEdge> createImporter() {
    VertexProvider<GSVertex> vertexProvider =
        (id, attributes) -> {
          GSVertex gv = new GSVertex(id);

          if (attributes.containsKey("Country")) {
            String country = attributes.get("Country").getValue();
            gv.setCountry(country);
          }

          return gv;
        };

    EdgeProvider<GSVertex, GSEdge> edgeProvider =
        (from, to, label, attributes) -> {
          GSEdge ge = new GSEdge(from, to);
          if (label != null && !label.equals("")) {
            ge.setLabelRepresentative(label);
          }

          return ge;
        };

    GraphMLImporter<GSVertex, GSEdge> importer =
        new GraphMLImporter<>(vertexProvider, edgeProvider);

    return importer;
  }
}
