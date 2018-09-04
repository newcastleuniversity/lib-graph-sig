package eu.prismacloud.primitives.zkpgs.graph;

import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.io.File;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Set;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphMLImporter;
import org.jgrapht.io.ImportException;

/**
 * Encapsulates a graph of the graph signature scheme.
 *
 * <p>The method factory method createGraph(String filename) is used to instantiate such a graph
 * from a serialized graphml representation.
 *
 * @param <V> vertex type, required to be a subclass of GSVertex
 * @param <E> edge type, required to be a subclass of GSEdge
 */
public class GSGraph<
V extends eu.prismacloud.primitives.zkpgs.graph.GSVertex,
E extends eu.prismacloud.primitives.zkpgs.graph.GSEdge>
implements Serializable, Cloneable {

	/** */
	private static final long serialVersionUID = -3556647651640740630L;

	private DefaultUndirectedGraph<V, E> graph;

	/**
	 * Creates a new GSGraph with the corresponding vertices and edges after parsing a graphml file.
	 *
	 * @param graph the graph
	 */
	GSGraph(DefaultUndirectedGraph<V, E> graph) {
		super();
		this.graph = graph;
	}

	/**
	 * Factory method that creates a graph structure with a number of vertices and edges after
	 * importing the graphml file.
	 *
	 * @param graphFile the graph file
	 * @return GSGraph encapsulating a jgrapht graph
	 * @throws ImportException the import exception
	 */
	public static GSGraph<GSVertex, GSEdge> createGraph(final String graphFile)
			throws ImportException {
		DefaultUndirectedGraph<GSVertex, GSEdge> graph = new DefaultUndirectedGraph<>(GSEdge.class);

		GraphMLImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();
		File file = GraphMLProvider.getGraphMLFile(graphFile);
		importer.importGraph(graph, file);

		return new GSGraph<GSVertex, GSEdge>(graph);
	}

	/**
	 * Encodes a graph that has been constructed from an imported graphml file with a specified encoding. 
	 * Vertex and label representatives are obtained from an IGraphEncoding.
	 *
	 * @param encoding an IGraphEncoding which is meant to encode this graph.
	 * 
	 * @throws EncodingException if the encoding cannot encode a given vertex id or label String
	 * with a prime number. The encoding is usually on a finite set of distinct strings.
	 * Thereby, an EncodingException will occur if a vertex id or label is requested which is not
	 * in this finite set.
	 */
	public void encodeGraph(IGraphEncoding encoding) throws EncodingException {
		encodeVertices(encoding);
		encodeEdges(encoding);
	}

	private void encodeVertices(IGraphEncoding encoding) throws EncodingException {
		Set<V> vertexSet = this.graph.vertexSet();
		for (V vertex : vertexSet) {
			encodeVertex(vertex, encoding);
		}
	}

	/**
	 * Encodes a single vertex with a given encoding.
	 * 
	 * @param vertex to be encoded
	 * @param encoding IGraphEncoding to be used
	 * 
	 * @throws EncodingException if this particular vertex cannot be encoded, either
	 * because the vertex id or a label string is not found represented in the encoding.
	 */
	private void encodeVertex(V vertex, IGraphEncoding encoding) throws EncodingException {
		// Set Vertex Representative
		vertex.setVertexRepresentative(encoding.getVertexRepresentative(vertex.getId()));

		// List of Vertex Label Representatives
		ArrayList<BigInteger> vertexLabelRepresentatives = new ArrayList<>();
		if ((vertex.getLabels() != null) && (!vertex.getLabels().isEmpty())) {
			for (String label : vertex.getLabels()) {
				BigInteger labelRepresentative = encoding.getVertexLabelRepresentative(label);
				Assert.notNull(
						labelRepresentative, "The encoding returned null as a vertex label.");
				vertexLabelRepresentatives.add(labelRepresentative);
			}
		}
		vertex.setLabelRepresentatives(vertexLabelRepresentatives);
	}

	private void encodeEdges(IGraphEncoding encoding) throws EncodingException {
		Set<E> edgeSet = this.graph.edgeSet();
		for (E edge : edgeSet) {
			encodeEdge(edge, encoding);
		}
	}

	/**
	 * Encodes a single edge with a given encoding.
	 * 
	 * @param edge to be encoded
	 * @param encoding IGraphEncoding to be used
	 * 
	 * @throws EncodingException if this particular edge cannot be encoded, because
	 * a label string is not found represented in the encoding.
	 */
	private void encodeEdge(E edge, IGraphEncoding encoding) throws EncodingException {
		// Vertex representatives already encoded by the GSVertex instances referenced by the edge 

		// List of Edge Label Representatives
		ArrayList<BigInteger> edgeLabelRepresentatives = new ArrayList<>();
		if ((edge.getLabels() != null) && (!edge.getLabels().isEmpty())) {
			for (String label : edge.getLabels()) {
				BigInteger labelRepresentative = encoding.getEdgeLabelRepresentative(label);
				Assert.notNull(
						labelRepresentative, "The encoding returned null as an edge label.");
				edgeLabelRepresentatives.add(labelRepresentative);
			}
		}
		edge.setLabelRepresentatives(edgeLabelRepresentatives);
	}

	/**
	 * Returns the encapsulated Graph instance.
	 *
	 * @return the graph
	 */
	public Graph<V, E> getGraph() {
		return graph;
	}

	@SuppressWarnings("unchecked")
	@Override
	public GSGraph<V, E> clone() {
		GSGraph<V, E> theClone = null;

		try {
			theClone = (GSGraph<V, E>) super.clone();
		} catch (CloneNotSupportedException e) {
			// Should never happen
			throw new InternalError(e);
		}

		// Cloning mutable members
		theClone.graph = (DefaultUndirectedGraph<V, E>) graph.clone();

		return theClone;
	}
}
