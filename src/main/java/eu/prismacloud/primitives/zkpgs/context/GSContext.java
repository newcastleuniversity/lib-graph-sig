package eu.prismacloud.primitives.zkpgs.context;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** Represents the public knowledge before the proof */
public class GSContext implements IContext, IContextProducer {
	private List<String> ctxList = new ArrayList<String>();

	private final ExtendedPublicKey extendedPublicKey;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private Logger gslog = GSLoggerConfiguration.getGSlog();

	public GSContext(
			final ExtendedPublicKey extendedPublicKey) {
		Assert.notNull(extendedPublicKey, "extended public key must not be null");
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
	}

	public List<String> computeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();
		addToChallengeContext(ctxList);
		return ctxList;
	}

	public void addToChallengeContext(List<String> ctxList) {
		keyGenParameters.addToChallengeContext(ctxList);
		extendedPublicKey.addToChallengeContext(ctxList);
	}

	/**
	 * TODO Old computeChallengeContext method. To be transfered to test cases.
	 * @deprecated
	 * @return
	 */
	public List<String> oldComputeChallengeContext() {
		List<String> ctxList = new ArrayList<String>();

		SignerPublicKey publicKey = extendedPublicKey.getPublicKey();
		Map<URN, BaseRepresentation> bases = extendedPublicKey.getBases();
		Map<URN, BigInteger> labels = extendedPublicKey.getLabelRepresentatives();

		keyGenParameters.addToChallengeContext(ctxList);

		publicKey.addToChallengeContext(ctxList);

		for (BaseRepresentation baseRepresentation : bases.values()) {
			baseRepresentation.addToChallengeContext(ctxList);
		}

		for (BigInteger label : labels.values()) {
			ctxList.add(String.valueOf(label));
		}

		graphEncodingParameters.addToChallengeContext(ctxList);

		return ctxList;
	}

	public void computeWitnessContext(List<String> witnesses) {
		for (String element : witnesses) {
			ctxList.add(element);
		}
	}

	public void clearContext() {
		ctxList.clear();
	}
}
