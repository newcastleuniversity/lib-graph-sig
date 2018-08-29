package eu.prismacloud.primitives.zkpgs.parameters;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;

/** 
 * Representation of the graph encoding parameters.
 * 
 * <p>As a default, the label encoding will get the reserved space lPrime_L 
 * of least primes, that is, label representatives are guaranteed to be
 * less than lPrime_L in bitlength. 
 * 
 * <p>The primes for vertex encoding are guaranteed to be encoded in the bitlength interval
 * [lPrime_L, lPrime_V].
 * */
public class GraphEncodingParameters implements IContextProducer {
	/** Maximal number of vertices to be encoded */
	private final int l_V;

	/**
	 * Reserved bit length for vertex encoding (bit length of the largest encodeable prime
	 * representative)
	 */
	private final int lPrime_V;

	/** Maximal number of edges to be encoded */
	private final int l_E;

	/** Maximal number of labels to be encoded */
	private final int l_L;

	/** Reserved bit length for label encoding */
	private final int lPrime_L;
	
	private final BigInteger minLabelRep;

	private final BigInteger minVertexRep;
	

	/**
	 * Instantiates a new Graph encoding parameters.
	 *
	 * @param l_V the maximal number of vertices to be encoded
	 * @param lPrime_V the bit length for vertex encoding
	 * @param l_E the maximal number of edges to be encoded
	 * @param l_L the maximal number of labels to be encoded
	 * @param lPrime_L the reserved bit length for label encoding
	 * @pre \( l_V != null \and lPrime_V != null \and l_E != null \and l_L != null \and lPrime_L != null\)
	 * @post
	 */
	public GraphEncodingParameters(int l_V, int lPrime_V, int l_E, int l_L, int lPrime_L) {
		Assert.notNull(l_V, "l_V parameter must not be null");
		Assert.notNull(lPrime_V, "lPrime_V parameter must not be null");
		Assert.notNull(l_E, "l_E parameter must not be null");
		Assert.notNull(l_L, "l_L parameter must not be null");
		Assert.notNull(lPrime_L, "lPrime_L parameter must not be null");

		this.l_V = l_V;
		this.lPrime_V = lPrime_V;
		this.l_E = l_E;
		this.l_L = l_L;
		this.lPrime_L = lPrime_L;
		
		this.minLabelRep = NumberConstants.TWO.getValue();
		this.minVertexRep = NumberConstants.TWO.getValue().pow(this.lPrime_L).nextProbablePrime();
	}

	/**
	 * Gets l v.
	 *
	 * @return the l v
	 */
	public int getL_V() {
		return l_V;
	}

	/**
	 * Gets l prime v.
	 *
	 * @return the l prime v
	 */
	public int getlPrime_V() {
		return lPrime_V;
	}

	/**
	 * Gets l e.
	 *
	 * @return the l e
	 */
	public int getL_E() {
		return l_E;
	}

	/**
	 * Gets l l.
	 *
	 * @return the l l
	 */
	public int getL_L() {
		return l_L;
	}

	/**
	 * Gets l prime l.
	 *
	 * @return the l prime l
	 */
	public int getlPrime_L() {
		return lPrime_L;
	}

	@Override
	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		addToChallengeContext(ctxList);
		return ctxList;
	}

	@Override
	public void addToChallengeContext(List<String> ctxList) {
		ctxList.add(String.valueOf(this.getL_V()));
		ctxList.add(String.valueOf(this.getlPrime_V()));
		ctxList.add(String.valueOf(this.getL_E()));
		ctxList.add(String.valueOf(this.getL_L()));
		ctxList.add(String.valueOf(this.getlPrime_L()));
	}
	
	public BigInteger getLeastLabelRepresentative() {
		return this.minLabelRep;
	}
	
	public BigInteger getLeastVertexRepresentative() {
		return this.minVertexRep;
	}
}
