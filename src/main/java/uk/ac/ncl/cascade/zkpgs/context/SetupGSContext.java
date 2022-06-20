/**
 * 
 */
package uk.ac.ncl.cascade.zkpgs.context;

import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.util.Assert;

import java.util.ArrayList;
import java.util.List;

/**
 * Holds the context during setup and signing proofs, before an ExtendedPublicKey is established.
 *
 */
public class SetupGSContext implements IContext, IContextProducer {

	private final List<String> ctxList = new ArrayList<String>();
	private final SignerPublicKey publicKey;
	private final KeyGenParameters keyGenParameters;

	//private Logger gslog = GSLoggerConfiguration.getGSlog();

	public SetupGSContext(
			final SignerPublicKey signerPublicKey) {
		Assert.notNull(signerPublicKey, "signer public key must not be null");
		this.publicKey = signerPublicKey;
		this.keyGenParameters = signerPublicKey.getKeyGenParameters();
	}

	/* (non-Javadoc)
	 * @see eu.prismacloud.primitives.zkpgs.context.IContext#computeChallengeContext()
	 */
	@Override
	public List<String> computeChallengeContext() {
		keyGenParameters.addToChallengeContext(ctxList);

		publicKey.addToChallengeContext(ctxList);

		return ctxList;
	}

	/* (non-Javadoc)
	 * @see eu.prismacloud.primitives.zkpgs.context.IContext#computeWitnessContext(java.util.List)
	 */
	@Override
	public void computeWitnessContext(List<String> witnesses) {
		for (String element : witnesses) {
			ctxList.add(element);
		}
	}

	/* (non-Javadoc)
	 * @see eu.prismacloud.primitives.zkpgs.context.IContext#clearContext()
	 */
	@Override
	public void clearContext() {
		ctxList.clear();
	}

	@Override
	public void addToChallengeContext(List<String> ctx) {
		keyGenParameters.addToChallengeContext(ctx);

		publicKey.addToChallengeContext(ctx);
	}
}
