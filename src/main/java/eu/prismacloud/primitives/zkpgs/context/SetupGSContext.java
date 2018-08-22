/**
 * 
 */
package eu.prismacloud.primitives.zkpgs.context;

import eu.prismacloud.primitives.zkpgs.keys.SignerPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Holds the context during setup and signing proofs, before an ExtendedPublicKey is established.
 *
 */
public class SetupGSContext implements IContext {

	private final List<String> ctxList = new ArrayList<String>();
	private final SignerPublicKey publicKey;
	private final KeyGenParameters keyGenParameters;

	private Logger gslog = GSLoggerConfiguration.getGSlog();

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
		addKeyGenParameters(keyGenParameters);

		ctxList.add(String.valueOf(publicKey.getModN()));
		ctxList.add(String.valueOf(publicKey.getBaseS().getValue()));
		ctxList.add(String.valueOf(publicKey.getBaseZ().getValue()));
		ctxList.add(String.valueOf(publicKey.getBaseR().getValue()));
		ctxList.add(String.valueOf(publicKey.getBaseR_0().getValue()));

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

	private void addKeyGenParameters(KeyGenParameters keyGenParameters) {
		ctxList.add(String.valueOf(keyGenParameters.getL_n()));
		ctxList.add(String.valueOf(keyGenParameters.getL_gamma()));
		ctxList.add(String.valueOf(keyGenParameters.getL_rho()));
		ctxList.add(String.valueOf(keyGenParameters.getL_m()));
		ctxList.add(String.valueOf(keyGenParameters.getL_res()));
		ctxList.add(String.valueOf(keyGenParameters.getL_e()));
		ctxList.add(String.valueOf(keyGenParameters.getL_prime_e()));
		ctxList.add(String.valueOf(keyGenParameters.getL_v()));
		ctxList.add(String.valueOf(keyGenParameters.getL_statzk()));
		ctxList.add(String.valueOf(keyGenParameters.getL_H()));
		ctxList.add(String.valueOf(keyGenParameters.getL_r()));
		ctxList.add(String.valueOf(keyGenParameters.getL_pt()));
	}

}
