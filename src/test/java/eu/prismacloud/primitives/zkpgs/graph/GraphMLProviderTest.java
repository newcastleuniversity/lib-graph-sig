package eu.prismacloud.primitives.zkpgs.graph;

import eu.prismacloud.primitives.zkpgs.DefaultValues;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphImporter;
import org.jgrapht.io.ImportException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.InputStream;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/** */
class GraphMLProviderTest {
    private Logger gslog = GSLoggerConfiguration.getGSlog();

    @BeforeEach
    void setUp() {
    }

    @Test
    void getGraphMLFile() {
        File file = GraphMLProvider.getGraphMLFile(DefaultValues.SIGNER_GRAPH_FILE);
        assertNotNull(file);
    }


    @Test
    void getGraphMLStream() {
        InputStream is = GraphMLProvider.getGraphMLStream(DefaultValues.SIGNER_GRAPH_FILE);
        assertNotNull(is);
    }

    @Test
    @RepeatedTest(10)
    void createImporter() throws ImportException {

        Graph<GSVertex, GSEdge> graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

        GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
        assertNotNull(importer);
        File file = GraphMLProvider.getGraphMLFile(DefaultValues.SIGNER_GRAPH_FILE);
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


    @Test
    @RepeatedTest(10)
    void createImporterStream() throws ImportException {

        Graph<GSVertex, GSEdge> graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

        GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
        assertNotNull(importer);
        InputStream is = GraphMLProvider.getGraphMLStream(DefaultValues.SIGNER_GRAPH_FILE);
        assertNotNull(is);

        importer.importGraph(graph, is);

        assertNotNull(graph);
        assertTrue(!graph.vertexSet().isEmpty());
        assertTrue(!graph.edgeSet().isEmpty());
        gslog.info("vertex size: " + graph.vertexSet().size());
        gslog.info("edge size: " + graph.edgeSet().size());
        assertEquals(15, graph.vertexSet().size());
        assertEquals(14, graph.edgeSet().size());
    }
}
