package eu.prismacloud.primitives.zkpgs.keys;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.context.IContextProducer;
import eu.prismacloud.primitives.zkpgs.encoding.IGraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.EncodingException;
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
public class ExtendedPublicKey implements Serializable, IPublicKey, IContextProducer, IGraphEncoding {
	private static final long serialVersionUID = 603738248933483649L;
	private final SignerPublicKey signerPublicKey;
	private Map<URN, BaseRepresentation> bases;
	private final transient GraphEncodingParameters graphEncodingParameters;
	private BaseCollectionImpl baseCollection;
	private final IGraphEncoding graphEncoding;

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
	@Override
	public Map<URN, BigInteger> getLabelRepresentatives() {
		return this.graphEncoding.getLabelRepresentatives();
	}

	/**
	 * Gets vertex representatives.
	 *
	 * @return the vertex representatives
	 */
	@Override
	public Map<URN, BigInteger> getVertexRepresentatives() {
		return this.graphEncoding.getVertexRepresentatives();
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

	    // Intentionally removed labels from context, not specified as such.
//	    for (BigInteger label : getLabelRepresentatives().values()) {
//	      ctxList.add(String.valueOf(label));
//	    }

	    graphEncodingParameters.addToChallengeContext(ctxList);
	}
	
	@Override
	public void setupEncoding() throws EncodingException {
		this.graphEncoding.setupEncoding();
	}
}
