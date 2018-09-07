package eu.prismacloud.primitives.zkpgs.util;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.jgrapht.io.ImportException;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.encoding.GeoLocationGraphEncoding;
import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;

/**
 * Utility functions to display and diagnose the structure of a graph representation.
 */
public class GraphUtils {
	
	/**
	 * Returns a String representation of an iterator over BaseRepresenation instances.
	 * Displays the type of the base and the index of the base.
	 * 
	 * @param iterator Iterator of BaseRepresentations
	 * 
	 * @return compact String representation of the graph.
	 */
	public static String iteratedGraphToString(Iterator<BaseRepresentation> iterator) {
		StringBuilder sb = new StringBuilder("G[ ");
		while (iterator.hasNext()) {
			BaseRepresentation baseRepresentation = (BaseRepresentation) iterator.next();
			sb.append(graphTypeToString(baseRepresentation));
			sb.append(baseRepresentation.getBaseIndex());
			if (iterator.hasNext()) sb.append(", ");
		}
		sb.append(" ]");
		return sb.toString();
	}

	/**
	 * Returns a String representation of an iterator over BaseRepresenation instances including the URN keys of their exponents.
	 * Displays the type of the base, the index of the base, and the URN key of the exponent in the ProofStore.
	 * 
	 * @param iterator Iterator of BaseRepresentations
	 * 
	 * @return compact String representation of the graph.
	 */
	public static String iteratedGraphToExpString(Iterator<BaseRepresentation> iterator, ProofStore<Object> ps) {
		StringBuilder sb = new StringBuilder("G[ ");
		while (iterator.hasNext()) {
			BaseRepresentation baseRepresentation = (BaseRepresentation) iterator.next();
			sb.append(graphTypeToString(baseRepresentation));
			sb.append(baseRepresentation.getBaseIndex());
			sb.append('^');
			
			String expKey = expKeyToString(baseRepresentation, ps);
			if (expKey == null) { 
				sb.append('%');
			} else {
				sb.append(expKey);
			}
			if (iterator.hasNext()) sb.append(", ");
		}
		sb.append(" ]");
		return sb.toString();
	}

	/**
	 * Returns a concise String representation of the base type, where
	 * 'V' represents a vertex, 'E' represents an edge and '*' represents other types.
	 * 
	 * @param baseRepresentation BaseRepresentation to analyze.
	 * 
	 * @return concise String type
	 */
	public static String graphTypeToString(BaseRepresentation baseRepresentation) {
		switch(baseRepresentation.getBaseType()) {
		case VERTEX: return "V";
		case EDGE: return "E";
		default: 
		}
		return "*";
	}
	
	/**
	 * Returns a short representation of an exponent key as represented in a ProofStore.
	 * Conventionally, the method will return the suffix of the URN.
	 * 
	 * @param baseRepresentation BaseRepresentation to analyze.
	 * @param ps ProofStore where the exponent in question is stored.
	 * 
	 * @return String suffix or the URN or "%" is the URN was not found or the exponent null.
	 */
	public static String expKeyToString(BaseRepresentation baseRepresentation, ProofStore<Object> ps) {
		BigInteger exp = baseRepresentation.getExponent();
		URN urn = ps.getKey(exp);
		if (urn != null) {
			return urnToShortString(urn);
		} else {
			return "%";
		}
	}
	
	/**
	 * Extracts the suffix String of an URN.
	 * 
	 * @param urn URN to analyze.
	 * 
	 * @return Last suffix with delimeter "."
	 */
	public static String urnToShortString(URN urn) {
		StringTokenizer tokenizer = new StringTokenizer(urn.toHumanReadableString(), ".");
		String token = null;
		while (tokenizer.hasMoreTokens()) {
			token = tokenizer.nextToken();
		}
		return token;
	}
	
	/**
	 * Creates a new graph based on a graph file and an extended public key.
	 * The method seeks to establish a default geo-location encoding and
	 * to embed the GSGraph into a GraphRepresentation including randomly selected bases.
	 * 
	 * @param graphFilename filename of the GraphML file to be read.
	 * @param epk An ExtendedPublicKey to provide the encoding
	 * 
	 * @return A GraphRepresentation that encapsulates an encoded GSGraph as well as the
	 * base allocation. 
	 * 
	 * @throws ImportException if the GraphML file cannot be imported.
	 * @throws EncodingException if the GSGraph cannot be encoded with the given encoding.
	 */
	public static GraphRepresentation createGraph(String graphFilename, ExtendedPublicKey epk) throws ImportException, EncodingException {
		return createGraph(graphFilename, null, epk);
	}
	
	/**
	 * Creates a new graph based on a graph file and an extended public key,
	 * including co-encoded master secret key msk.
	 * The method seeks to establish a default geo-location encoding and
	 * to embed the GSGraph into a GraphRepresentation including randomly selected bases.
	 * 
	 * @param graphFilename filename of the GraphML file to be read.
	 * @param msk master secret key. Should this parameter be null, 
	 * then a GraphRepresentation without encoded R_0 is returned.
	 * @param epk An ExtendedPublicKey to provide the encoding
	 * 
	 * @return A GraphRepresentation that encapsulates an encoded GSGraph as well as the
	 * base allocation. 
	 * 
	 * @throws ImportException if the GraphML file cannot be imported.
	 * @throws EncodingException if the GSGraph cannot be encoded with the given encoding.
	 */
	public static GraphRepresentation createGraph(String graphFilename, BigInteger msk, ExtendedPublicKey epk) throws ImportException, EncodingException {
		
		GSGraph<GSVertex, GSEdge> gsGraph = GSGraph.createGraph(graphFilename);
		Assert.notNull(gsGraph, "Graph could not be created from graphml file.");

		IGraphEncoding encoding = new GeoLocationGraphEncoding(epk.getGraphEncodingParameters());
		encoding.setupEncoding();
		gsGraph.encodeGraph(encoding);

		GraphRepresentation gr = GraphRepresentation.encodeGraph(gsGraph, epk);
		
		if (msk != null) {
			BaseCollection collection = gr.getEncodedBaseCollection();
			BaseRepresentation baseR_0 =
					new BaseRepresentation(epk.getPublicKey().getBaseR_0(), msk, -1, BASE.BASE0);
			collection.add(baseR_0);
		}
				
		return gr;
	}
}
