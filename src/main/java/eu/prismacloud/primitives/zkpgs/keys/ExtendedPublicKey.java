package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.JsonIsoCountries;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The type Extended public key. */
public class ExtendedPublicKey implements Serializable, IPublicKey, IContextProducer {
	private static final long serialVersionUID = 603738248933483649L;
	private final SignerPublicKey signerPublicKey;
	private ExtendedPublicKey ePublicKey;
	private ExtendedPrivateKey ePrivateKey;
	private Map<URN, BaseRepresentation> bases;
	private Map<URN, BigInteger> discLogOfVertexBases;
	private Map<URN, BigInteger> discLogOfEdgeBases;
	private final Map<URN, BigInteger> labelRepresentatives;
	private final transient GraphEncodingParameters graphEncodingParameters;
	private JsonIsoCountries jsonIsoCountries;
	private Map<URN, BigInteger> countryLabels;
	private BaseRepresentation base;
	private int index = 0;
	private Map<URN, BigInteger> vertexRepresentatives;
	private BigInteger vertexPrimeRepresentative;
	private BaseCollectionImpl baseCollection;

	/**
	 * Instantiates a new Extended public key.
	 *
	 * @param signerPublicKey the signer key pair
	 * @param bases the bases
	 * @param vertexRepresentatives the vertex representatives
	 * @param labelRepresentatives the labels representatives
	 * @param graphEncodingParameters the graph encoding parameters
	 */
	public ExtendedPublicKey(
			final SignerPublicKey signerPublicKey,
			final Map<URN, BaseRepresentation> bases,
			final Map<URN, BigInteger> vertexRepresentatives,
			final Map<URN, BigInteger> labelRepresentatives,
			final GraphEncodingParameters graphEncodingParameters) {

		Assert.notNull(signerPublicKey, "public key must not be null");
		Assert.notNull(bases, "bases must not be null");
		Assert.notNull(vertexRepresentatives, "vertex representatives must not be null");
		Assert.notNull(labelRepresentatives, "labels representatives must not be null");
		Assert.notNull(graphEncodingParameters, "graph encoding parameters must not be null");

		this.signerPublicKey = signerPublicKey;
		this.bases = bases;
		this.vertexRepresentatives = vertexRepresentatives;
		this.labelRepresentatives = labelRepresentatives;
		this.graphEncodingParameters = graphEncodingParameters;
		this.baseCollection = new BaseCollectionImpl();
	}

	/**
	 * Gets public key.
	 *
	 * @return the public key
	 */
	public SignerPublicKey getPublicKey() {
		return this.signerPublicKey;
	}

	/**
	 * Gets bases.
	 *
	 * @return the vertex bases
	 */
	public Map<URN, BaseRepresentation> getBases() {
		return this.bases;
	}

	/**
	 * Gets base collection.
	 *
	 * @return the base collection
	 */
	public BaseCollection getBaseCollection() {
		baseCollection.setBases(new ArrayList<BaseRepresentation>(bases.values()));
		return baseCollection;
	}

	/**
	 * Gets labels representatives.
	 *
	 * @return the country labels
	 */
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return this.labelRepresentatives;
	}

	/**
	 * Gets vertex representatives.
	 *
	 * @return the vertex representatives
	 */
	public Map<URN, BigInteger> getVertexRepresentatives() {
		return this.vertexRepresentatives;
	}

	/**
	 * Returns the key generation parameters realized with this public key.
	 * @return
	 */
	public KeyGenParameters getKeyGenParameters() {
		return this.signerPublicKey.getKeyGenParameters();
	}

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

	    for (BigInteger label : getLabelRepresentatives().values()) {
	      ctxList.add(String.valueOf(label));
	    }

	    graphEncodingParameters.addToChallengeContext(ctxList);
	}
}
