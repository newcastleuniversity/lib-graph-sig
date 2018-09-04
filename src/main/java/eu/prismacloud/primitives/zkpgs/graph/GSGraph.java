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

	//	/**
	//	 * Encodes a graph that has been constructed from an imported graphml file with random vertex
	//	 * prime representatives. Selects a random prime vertex prime representative for each vertex and
	//	 * its prime representatives for the labels. The edge prime representative is selected and its
	//	 * prime representatives for the labels.
	//	 *
	//	 * <p>The labels are enforced to be geo-location labels (UN ISO country codes) and restricted to a
	//	 * single label.
	//	 *
	//	 * <p>Note that the method comes with a slight risk of a collision between randomly chosen vertex
	//	 * identifiers, making the graph representation ambiguous. It will also make it impossible for a
	//	 * verifier to effectively determine vertex identifiers for his queries. Further, the method is
	//	 * computationally intensive as many random prime numbers will be chosen.
	//	 *
	//	 * @param graphEncodingParameters the graph encoding parameters
	//	 * @deprecated
	//	 */
	//	@Deprecated
	//	public void encodeRandomGeoLocationGraph(GraphEncodingParameters graphEncodingParameters) {
	//		JsonIsoCountries jsonIsoCountries = new JsonIsoCountries();
	//		BigInteger vertexPrimeRepresentative;
	//		BigInteger labelPrimeRepresentative;
	//
	//		Set<V> vertexSet = this.graph.vertexSet();
	//		ArrayList<BigInteger> vertexLabelRepresentatives = new ArrayList<>();
	//		ArrayList<BigInteger> edgeLabelRepresentatives = new ArrayList<>();
	//		Map<URN, BigInteger> countryMap = jsonIsoCountries.getCountryMap();
	//		for (V vertex : vertexSet) {
	//			vertexLabelRepresentatives = new ArrayList<>();
	//
	//			if ((vertex.getLabels() != null) && (!vertex.getLabels().isEmpty())) {
	//				for (String label : vertex.getLabels()) {
	//					labelPrimeRepresentative = countryMap.get(URN.createZkpgsURN(label));
	//					Assert.notNull(
	//							labelPrimeRepresentative, "JsonIsoCountries returned null as a vertex label.");
	//					vertexLabelRepresentatives.add(labelPrimeRepresentative);
	//				}
	//			}
	//
	//			vertexPrimeRepresentative =
	//					CryptoUtilsFacade.generateRandomPrime(graphEncodingParameters.getlPrime_V());
	//			// TODO not correct: Needs to encode systematically.
	//			vertex.setVertexRepresentative(vertexPrimeRepresentative);
	//			vertex.setLabelRepresentatives(vertexLabelRepresentatives);
	//		}
	//
	//		Set<E> edgeSet = graph.edgeSet();
	//
	//		// TODO does not seem to establish edge encoding (product of the two vertices).
	//		for (eu.prismacloud.primitives.zkpgs.graph.GSEdge edge : edgeSet) {
	//
	//			if ((edge.getLabels() != null) && (!edge.getLabels().isEmpty())) {
	//				for (String label : edge.getLabels()) {
	//					labelPrimeRepresentative = countryMap.get(URN.createZkpgsURN(label));
	//					Assert.notNull(
	//							labelPrimeRepresentative, "JsonIsoCountries returned null as a edge label.");
	//					edgeLabelRepresentatives.add(labelPrimeRepresentative);
	//				}
	//				edge.setLabelRepresentatives(edgeLabelRepresentatives);
	//			}
	//		}
	//	}

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
