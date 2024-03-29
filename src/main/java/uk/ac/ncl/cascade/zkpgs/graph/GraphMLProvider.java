package uk.ac.ncl.cascade.zkpgs.graph;

import org.jgrapht.io.EdgeProvider;
import org.jgrapht.io.GraphMLImporter;
import org.jgrapht.io.VertexProvider;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;

/**
 * Imports a graphml file with the graph structure of the cloud infrastructure.
 */
public class GraphMLProvider {

    private static final String EMPTY_LABEL = "";

    private GraphMLProvider() {
    }

    /**
     * Returns the graphml file that describes the structure of the graph. The graphml file is
     * retrieved from the resources folder.
     *
     * @param graphFile the name of the graphml file
     * @return the graphml file
     */
    public static File getGraphMLFile(String graphFile) {
        ClassLoader classLoader = GraphMLProvider.class.getClassLoader();
        return new File(classLoader.getResource(graphFile).getFile());
    }

    /**
     * Returns an input stream with the contents of the graphml file that describes the structure of the graph.
     * The graphml file is retrieved from the resources folder.
     *
     * @param graphFile the graph file
     * @return the graphml file input stream
     */
    public static InputStream getGraphMLStream(String graphFile) {
        ClassLoader classLoader = GraphMLProvider.class.getClassLoader();
        return classLoader.getResourceAsStream(graphFile);
    }

    /**
     * Creates an importer instance to import the graphml file. We create a vertex provider that will
     * parse the graphml file and populate a new GSVertex object with the associated labels. For the
     * edge provider a new GSEdge object is created an populated with the associated labels.
     *
     * @return the graphml importer
     */
    public static GraphMLImporter<GSVertex, GSEdge> createImporter() {
        VertexProvider<GSVertex> vertexProvider =
                (id, attributes) -> {
                    ArrayList<String> labels = new ArrayList<String>();
                    GSVertex gv = new GSVertex(id, labels);
                    if (attributes.containsKey("Country")) {
                        String label = attributes.get("Country").getValue();
                        labels.add(label);
                    }
                    gv.setLabels(labels);
                    return gv;
                };

        EdgeProvider<GSVertex, GSEdge> edgeProvider =
                (from, to, label, attributes) -> {
                    GSEdge ge = new GSEdge(from, to);
                    ArrayList<String> labels = new ArrayList<String>();
                    if (!EMPTY_LABEL.equals(label)) {
                        if (attributes.containsKey("Country")) {
                            label = attributes.get("Country").getValue();
                            labels.add(label);
                        }
                        ge.setLabels(labels);
                    }
                    return ge;
                };

        return new GraphMLImporter<GSVertex, GSEdge>(vertexProvider, edgeProvider);
    }
}
