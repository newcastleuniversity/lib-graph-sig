package eu.prismacloud.primitives.zkpgs.util;

import java.math.BigInteger;
import java.util.Iterator;
import java.util.StringTokenizer;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;

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
}
