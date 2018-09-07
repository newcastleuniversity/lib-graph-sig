package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/** The type Extended public key. */
public class ExtendedPublicKey
implements Serializable, IPublicKey, IContextProducer, IExtendedKeyInfo, IBaseProvider {
	/* TODO make the keypair defensive and secure in that it is either completely immutable
	or only returns clones */

	private static final long serialVersionUID = 603738248933483649L;
	
	private final SignerPublicKey signerPublicKey;
	private Map<URN, BaseRepresentation> bases;
	private final GraphEncodingParameters graphEncodingParameters;
	private BaseCollectionImpl baseCollection;
	private final IGraphEncoding graphEncoding;

	/**
	 * Instantiates a new Extended public key.
	 *
	 * @param signerPublicKey the signer key pair
	 * @param bases the bases
	 * @param encoding the graph encoding used to encode the bases
	 * @param graphEncodingParameters the graph encoding parameters
	 */
	public ExtendedPublicKey(
			final SignerPublicKey signerPublicKey,
			final Map<URN, BaseRepresentation> bases,
			final IGraphEncoding encoding,
			final GraphEncodingParameters graphEncodingParameters) {

		Assert.notNull(signerPublicKey, "public key must not be null");
		Assert.notNull(bases, "bases must not be null");
		Assert.notNull(encoding, "Graph encoding must not be null");
		Assert.notNull(graphEncodingParameters, "graph encoding parameters must not be null");

		this.signerPublicKey = signerPublicKey;
		this.bases = bases;
		this.graphEncoding = encoding;
		this.graphEncodingParameters = graphEncodingParameters;
		this.baseCollection = new BaseCollectionImpl();
	}

	/**
	 * Returns the signer's public key.
	 *
	 * @return the public key
	 */
	public SignerPublicKey getPublicKey() {
		return this.signerPublicKey;
	}

	/**
	 * Returns a map of bases.
	 *
	 * @return the bases
	 */
	public Map<URN, BaseRepresentation> getBases() {
		return this.bases;
	}

	/**
	 * Returns a base collection.
	 *
	 * @return the base collection
	 */
	public BaseCollection getBaseCollection() {
		baseCollection.setBases(new ArrayList<BaseRepresentation>(bases.values()));
		return baseCollection;
	}

	/**
	 * Returns labels representatives used for encoding labels in graphs.
	 *
	 * @return the label prime representatives
	 */
	@Override
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return this.graphEncoding.getLabelRepresentatives();
	}

	/**
	 * Returns vertex prime representatives used for encoding vertices in a graph.
	 *
	 * @return the vertex prime representatives
	 */
	@Override
	public Map<URN, BigInteger> getVertexRepresentatives() {
		return this.graphEncoding.getVertexRepresentatives();
	}

	/**
	 * Returns the key generation parameters realized with the signer's public key.
	 *
	 * @return the key gen parameters
	 */
	@Override
	public KeyGenParameters getKeyGenParameters() {
		return this.signerPublicKey.getKeyGenParameters();
	}

	/**
	 * Returns the graph encoding parameters.
	 *
	 * @return the graph encoding parameters
	 */
	@Override
	public GraphEncodingParameters getGraphEncodingParameters() {
		return graphEncodingParameters;
	}

	@Override
	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		addToChallengeContext(ctxList);
		return ctxList;
	}

	@Override
	public void addToChallengeContext(List<String> ctxList) {
		this.signerPublicKey.addToChallengeContext(ctxList);

		for (BaseRepresentation baseRepresentation : getBases().values()) {
			baseRepresentation.addToChallengeContext(ctxList);
		}

		graphEncodingParameters.addToChallengeContext(ctxList);
	}

	@Override
	public void setupEncoding() throws EncodingException {
		this.graphEncoding.setupEncoding();
	}

	/**
	 * Returns the PROTOTYPE vertex base according to the index parameter. If the base does not exist in the
	 * bases map or the base type is not a vertex, then a IllegalArgumentException is thrown.
	 * 
	 * <p>Note that the method returns a reference to a prototypical vertex BaseRepresentation 
	 * and not a clone. Hence, this method must be used with care and its result should be
	 * cloned to avoid side-effects of the mutable BaseRepresentation.
	 *
	 * @param index the index of the base
	 * @return the vertex base
	 */
	protected BaseRepresentation getPrototypeVertexBase(int index) {
		BaseRepresentation base =
				bases.get(URN.createZkpgsURN("baseRepresentationMap.vertex.R_V_" + index));
		if (base == null) {
			throw new IllegalArgumentException("Requested vertex base did not exist. Index: " + index);
		}
		if (!base.getBaseType().equals(BASE.VERTEX)) {
			throw new IllegalArgumentException(
					"Vertex base candidate " + index + " is not classified as an vertex.");
		}
		return base;
	}

	/**
	 * Returns the PROTOTYPE edge base according to the index parameter. If the base does not exist in the bases
	 * map or the base type is not an edge, then a IllegalArgumentException is thrown.
	 * 
	 * <p>Note that the method returns a reference to a prototypical edge BaseRepresentation 
	 * and not a clone. Hence, this method must be used with care and its result should be
	 * cloned to avoid side-effects of the mutable BaseRepresentation.
	 *
	 * @param index the index
	 * @return the edge base
	 */
	protected BaseRepresentation getPrototypeEdgeBase(int index) {
		BaseRepresentation base =
				bases.get(URN.createZkpgsURN("baseRepresentationMap.edge.R_E_" + index));
		if (base == null) {
			throw new IllegalArgumentException("Requested edge base did not exist. Index: " + index);
		}
		if (!base.getBaseType().equals(BASE.EDGE)) {
			throw new IllegalArgumentException(
					"Edge base candidate " + index + " is not classified as an edge.");
		}
		return base;
	}
	
	/**
	 * Returns the vertex base according to the index parameter. If the base does not exist in the
	 * bases map or the base type is not a vertex, then a IllegalArgumentException is thrown.
	 * 
	 * <p>The result is a clone of the vertex base prototype
	 *
	 * @param index the index of the base
	 * @return the vertex base
	 */
	@Override
	public BaseRepresentation getVertexBase(int index) {
		return getPrototypeVertexBase(index).clone();
	}

	/**
	 * Returns the edge base according to the index parameter. If the base does not exist in the bases
	 * map or the base type is not an edge, then a IllegalArgumentException is thrown.
	 * 
	 * <p>The result is a clone of the edge base prototype.
	 *
	 * @param index the index
	 * @return the edge base
	 */
	@Override
	public BaseRepresentation getEdgeBase(int index) {
		return getPrototypeEdgeBase(index).clone();
	}

	/**
	 * Chooses uniformly at random a vertex base, excluding ones stated as being excludedBases.
	 *
	 * <p>The method is not guaranteed to terminate, should all possible vertex bases be excluded.
	 * 
	 * <p>The returned value is a clone and independent from the BaseRepresentation prototype.
	 *
	 * @param excludedBaseMap Map of bases to exclude
	 * @return BaseRepresentation of a fresh vertex base.
	 */
	@Override
	public BaseRepresentation getRandomVertexBase(Map<URN, BaseRepresentation> excludedBaseMap) {
		Collection<BaseRepresentation> excludedBases = excludedBaseMap.values();
		BaseRepresentation candidateBase = null;
		while (candidateBase == null || excludedBases.contains(candidateBase)) {
			candidateBase = getRandomVertexBase();
		}
		// Post-Condition: candidate is not null and candidate is not in excludedBases.
		return candidateBase.clone();
	}

	/**
	 * Chooses uniformly at random an edge base, excluding ones stated as being excludedBases.
	 *
	 * <p>The method is not guaranteed to terminate, should all possible edge bases be excluded.
	 * 
	 * <p>The returned value is a clone and independent from the BaseRepresentation prototype.
	 *
	 * @param excludedBaseMap Map of bases to exclude
	 * @return BaseRepresentation of a fresh edge base.
	 */
	@Override
	public BaseRepresentation getRandomEdgeBase(Map<URN, BaseRepresentation> excludedBaseMap) {
		Collection<BaseRepresentation> excludedBases = excludedBaseMap.values();
		BaseRepresentation candidateBase = null;
		while (candidateBase == null || excludedBases.contains(candidateBase)) {
			candidateBase = getRandomEdgeBase();
		}
		// Post-Condition: candidate is not null and candidate is not in excludedBases.
		return candidateBase.clone();
	}

	/**
	 * Chooses uniformly at random a vertex base.
	 * 
	 * <p>The returned value is a clone and independent from the BaseRepresentation prototype.
	 *
	 * @return BaseRepresentation of a fresh vertex base.
	 */
	@Override
	public BaseRepresentation getRandomVertexBase() {
		int minIndex = 1;
		int maxIndex = graphEncodingParameters.getL_V();
		int range = maxIndex - minIndex;

		SecureRandom secureRandom = new SecureRandom();
		int index = minIndex + secureRandom.nextInt(range);

		return getPrototypeVertexBase(index).clone();
	}

	/**
	 * Chooses uniformly at random an edge base.
	 * 
	 * <p>The returned value is a clone and independent from the BaseRepresentation prototype.
	 *
	 * @return BaseRepresentation of a fresh edge base.
	 */
	@Override
	public BaseRepresentation getRandomEdgeBase() {
		int minIndex = graphEncodingParameters.getL_V() + 1;
		int maxIndex = graphEncodingParameters.getL_V() + graphEncodingParameters.getL_E();
		int range = maxIndex - minIndex;

		SecureRandom secureRandom = new SecureRandom();
		int index = minIndex + secureRandom.nextInt(range);
		return getPrototypeEdgeBase(index).clone();
	}

	@Override
	public BigInteger getVertexRepresentative(String id) {
		return graphEncoding.getVertexRepresentative(id);
	}

	@Override
	public BigInteger getVertexLabelRepresentative(String label) {
		return graphEncoding.getVertexLabelRepresentative(label);
	}

	@Override
	public BigInteger getEdgeLabelRepresentative(String label) {
		return graphEncoding.getEdgeLabelRepresentative(label);
	}

	@Override
	public IGraphEncoding getEncoding() {
		return this.graphEncoding;
	}
}
