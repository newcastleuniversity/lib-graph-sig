package eu.prismacloud.primitives.zkpgs.encoding;

import java.math.BigInteger;
import java.util.Map;

import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.util.URN;

/** 
 * Interface for classes that offer representative encodings.
 * The encoding is responsible for mapping vertex and label strings
 * onto prime numbers that represent them.
 * 
 * <p>There is a separation of duty between the IGraphEncoding (holding the correspondence of
 * strings (vertex ids/labels) and prime representatives) and the GraphRepresentation (mapping 
 * these representatives to appropriate bases for a specific graph signature).
 */
public interface IGraphEncoding {

	/**
	 * Returns the GraphEncodingParameters that were used to generate
	 * this encoding.
	 */
	GraphEncodingParameters getGraphEncodingParameters();
	
	/**
	 * Returns the overall map of vertex representatives established
	 * in this encoding. That is, the map contains legal prime 
	 * representatives that can be used in a graph encoding
	 * alon with an URN.
	 * 
	 * @return Map of vertex representatives
	 */
	Map<URN, BigInteger> getVertexRepresentatives();
	
	/**
	 * Returns an overall map of label representatives offered in this
	 * encoding. The encoding may or may not differentiate between
	 * vertex and edge label representatives which should be 
	 * reflected in including vertex or edge in the URN.
	 * 
	 * @return Map of label representatives
	 */
	Map<URN, BigInteger> getLabelRepresentatives();
	
	/**
	 * Method to setup the encoding and check its consistency.
	 * Should be called before the encoding is put to work.
	 * 
	 * @throws EncodingException when the encoding is inconsistent
	 * or faulty.
	 */
	void setupEncoding() throws EncodingException;
	
	/**
	 * Returns a prime representative for a vertex based on a String id
	 * of that vertex in a graph.
	 * 
	 * @param id Identifier of the vertex
	 * 
	 * @return BigInteger prime representative
	 */
	BigInteger getVertexRepresentative(String id);
	
	/**
	 * Returns a prime representative for a vertex label based on a label string.
	 * The encoding may or may not enforce a distinction between vertex and edge labels.
	 * 
	 * @param label String label
	 * 
	 * @return BigInteger prime representative
	 */
	BigInteger getVertexLabelRepresentative(String label);
	
	/**
	 * Returns a prime representative for an edge label based on a label string.
	 * The encoding may or may not enforce a distinction between vertex and edge labels.
	 * 
	 * @param label String label
	 * 
	 * @return BigInteger prime representative
	 */
	BigInteger getEdgeLabelRepresentative(String label);
}
