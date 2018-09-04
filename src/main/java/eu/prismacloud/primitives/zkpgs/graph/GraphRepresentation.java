package eu.prismacloud.primitives.zkpgs.graph;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The GraphRepresentation holds a GSGraph encoded with an IGraphEncoding
 * and projected on selected (random) bases of an ExtendedPublicKey.
 * 
 * <p>The GraphRepresentation relies on a GSGraph having already been encoded
 * with an IGraphEncoding and holding appropriate prime representatives
 * for its vertices, edges and corresponding labels.
 * 
 * <p>The GraphRepresentation obtains bases from an ExtendedPublicKey to
 * encode the GSGraph onto them, that is, computing an appropriate exponent for 
 * each selected vertex and edge base.
 */
public class GraphRepresentation {
	
	//private Logger log = GSLoggerConfiguration.getGSlog();
	
	private final ExtendedPublicKey extendedPublicKey;
	private final GSGraph<GSVertex, GSEdge> gsGraph;
	private final Map<URN, BaseRepresentation> encodedBases = new LinkedHashMap<URN, BaseRepresentation>();
	private final Map<URN, BaseRepresentation> excludedBases = new HashMap<URN, BaseRepresentation>();

	protected GraphRepresentation(GSGraph<GSVertex, GSEdge> gsgraph, ExtendedPublicKey epk) {
		this.extendedPublicKey = epk;
		this.gsGraph = gsgraph;
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
	public static GraphRepresentation encodeGraph(GSGraph<GSVertex, GSEdge> gsGraph, ExtendedPublicKey epk) {
		GraphRepresentation gr = new GraphRepresentation(gsGraph, epk);

		gr.encodeVertices();
		gr.encodeEdges();

		return gr;
	}

	/**
	 * Encodes all vertices by looking up the vertex representative and corresponding label
	 * representatives from each GSVertex and selecting a random base from the 
	 * ExtendedPublicKey to encode them in.
	 */
	private void encodeVertices() {
		
		Set<GSVertex> vertexSet = this.gsGraph.getGraph().vertexSet();
		
		for (GSVertex vertex : vertexSet) {
			// Obtain a random base and exclude it from further selection
			BaseRepresentation base = extendedPublicKey.getRandomVertexBase(excludedBases); // clone
			excludedBases.put(URN.createZkpgsURN("bases.vertex.R_i_" + base.getBaseIndex()), base);
			Assert.notNull(base, "Cannot obtain an appropriate random base.");
			// Post-condition: getRandomVertexBase returns a clone that can be modified.

			
			BigInteger vertexRepresentative = vertex.getVertexRepresentative();
			Assert.notNull(vertexRepresentative, "The GSVertex does not hold a vertex representative");

//			log.info("Combining vertex: ("
//					+ vertex 
//					+ ") with vertex representative e_i=" 
//					+ vertex.getVertexRepresentative() 
//					+ ". There are " + vertex.getLabelRepresentatives().size() + " labels.");
			
			BigInteger exponentEncoding = encodeVertex(vertexRepresentative, vertex.getLabelRepresentatives());
			Assert.notNull(exponentEncoding, "Exponent encoding returned null.");

			Assert.notNull(base, "Cannot obtain an appropriate random base.");

			base.setExponent(exponentEncoding);

			encodedBases.put(URN.createZkpgsURN("bases.vertex.R_" + base.getBaseIndex()), base);
		}
	}

	/**
	 * Encodes all edging by looking up the vertex representatives and corresponding label
	 * representatives from each GSEdge and selecting a random base from the 
	 * ExtendedPublicKey to encode them in.
	 */
	private void encodeEdges() {

		Set<GSEdge> edgeSet = this.gsGraph.getGraph().edgeSet();

		for (GSEdge edge : edgeSet) {
			// Obtain a random base and exclude it from further selection
			BaseRepresentation base = extendedPublicKey.getRandomEdgeBase(excludedBases); // clone
			excludedBases.put(URN.createZkpgsURN("bases.edge.R_i_j_" + base.getBaseIndex()), base);
			Assert.notNull(base, "Cannot obtain an appropriate random base.");
			// Post-condition: getRandomEdgeBase returns a clone that can be modified.
			
			
			GSVertex v_i = edge.getV_i();
			GSVertex v_j = edge.getV_j();
			List<BigInteger> edgeLabels = edge.getLabelRepresentatives();

			Assert.notNull(edgeLabels, "Edge label set was found to be null.");
			Assert.notNull(v_i, "vertex edge was found to be null");
			Assert.notNull(v_j, "vertex edge was found to be null");
			
//			log.info("Combining edge: ("
//					+ edge.getV_i() + ", " + edge.getV_j() 
//					+ ") with vertex representatives e_i=" 
//					+ edge.getV_i().getVertexRepresentative() 
//					+ " and e_j="
//					+ edge.getV_j().getVertexRepresentative()
//					+ ". There are " + edge.getLabelRepresentatives().size() + " labels. "
//					+ "Vertex representative product="
//					+ edge.getV_i().getVertexRepresentative().multiply(edge.getV_j().getVertexRepresentative()));

			BigInteger exponentEncoding =
					encodeEdge(v_i.getVertexRepresentative(), v_j.getVertexRepresentative(), edgeLabels);

			Assert.notNull(exponentEncoding, "Edge exponent was found to be null.");

			base.setExponent(exponentEncoding);
			
			encodedBases.put(URN.createZkpgsURN("bases.edge.R_i_j_" + base.getBaseIndex()), base);
		}
	}

	/**
	 * Return the encoded bases.
	 *
	 * @return the encoded bases
	 */
	public Map<URN, BaseRepresentation> getEncodedBases() {
		return encodedBases;
	}

	/**
	 * Returns a new encoded base collection.
	 *
	 * @return the encoded base collection
	 */
	public BaseCollection getEncodedBaseCollection() {
		BaseCollectionImpl baseCollection = new BaseCollectionImpl();
		baseCollection.addAll(encodedBases.values());
		return baseCollection;
	}


	/**
	 * Encodes a single vertex exponent with a vertex prime representative and a list of 
	 * label prime representatives. The vertex prime representative is multiplied with 
	 * the list of label prime representatives.
	 * 
	 * @post The method must ensure that the BigInteger returned is not null.
	 * 
	 * @return BigInteger designated exponent representing the vertex
	 */
	private static BigInteger encodeVertex(
			BigInteger vertexPrimeRepresentative, List<BigInteger> labelRepresentatives) {

		Assert.notNull(vertexPrimeRepresentative, "Vertex prime representative does not exist");
		Assert.notNull(labelRepresentatives, "Labels prime representative does not exist");

		BigInteger e_k = BigInteger.ONE;
		if (labelRepresentatives != null) {
			for (BigInteger labelRepresentative : labelRepresentatives) {
				if (labelRepresentative != null) {
					e_k = e_k.multiply(labelRepresentative);
				}
			}
		}
		
		Assert.notNull(e_k, "Computed label product was null.");
		return vertexPrimeRepresentative.multiply(e_k);
	}

	/**
	 * Encodes an edge with the prime representatives of its vertices and a list of label 
	 * representatives of the edge. The vertex prime representatives are multiplied 
	 * with the list of label prime representatives.
	 * 
	 * 	 * @post The method must ensure that the BigInteger returned is not null.
	 * 
	 * @return BigInteger designated exponent representing the edge
	 */
	private static BigInteger encodeEdge(
			BigInteger e_i, BigInteger e_j, List<BigInteger> labelRepresentatives) {

		Assert.notNull(e_i, "Vertex representative e_i was found null.");
		Assert.notNull(e_j, "Vertex representative e_j was found null.");
		Assert.notNull(labelRepresentatives, "Labels prime representative does not exist");

		BigInteger e_k = BigInteger.ONE;
		if (labelRepresentatives != null) {
			for (BigInteger labelRepresentative : labelRepresentatives) {
				if (labelRepresentative != null) {
					e_k = e_k.multiply(labelRepresentative);
				}
			}
		}

		Assert.notNull(e_k, "Computed label product was null.");
		return e_i.multiply(e_j).multiply(e_k);
	}
}
