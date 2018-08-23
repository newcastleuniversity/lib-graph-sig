package eu.prismacloud.primitives.zkpgs.context;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import java.util.ArrayList;
import java.util.List;

/** Represents the public knowledge before the proof */
public class GSContext implements IContext, IContextProducer {
	private List<String> ctxList = new ArrayList<String>();

	private final ExtendedPublicKey extendedPublicKey;
	private final KeyGenParameters keyGenParameters;

	public GSContext(
			final ExtendedPublicKey extendedPublicKey) {
		Assert.notNull(extendedPublicKey, "extended public key must not be null");
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
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

	public void computeWitnessContext(List<String> witnesses) {
		for (String element : witnesses) {
			ctxList.add(element);
		}
	}

	public void clearContext() {
		ctxList.clear();
	}
}
