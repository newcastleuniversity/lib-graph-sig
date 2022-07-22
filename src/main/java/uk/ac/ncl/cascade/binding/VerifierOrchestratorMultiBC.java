package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Establishes an orchestrator of verifiers for multiple proofs of possession of binding credentials.
 */
public class VerifierOrchestratorMultiBC {

	private final ExtendedPublicKey extendedPublicKey;
	private final int bindingCredentialsNo;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private ArrayList<VerifierOrchestratorBC> bcVerifiers;

	public VerifierOrchestratorMultiBC(final ExtendedPublicKey extendedPublicKey, final int bindingCredentialsNo) {
		this.extendedPublicKey = extendedPublicKey;
		this.bindingCredentialsNo = bindingCredentialsNo;

	}


	public void executeVerifiers(List<IMessageGateway> messageGateways) throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException, VerificationException {

		VerifierOrchestratorBC bcVerifier;
		bcVerifiers = new ArrayList<VerifierOrchestratorBC>();

		for (int i = 0; i < bindingCredentialsNo; i++) {
			gslog.info("iteration: " + i);
			bcVerifier = new VerifierOrchestratorBC(this.extendedPublicKey, messageGateways.get(i));
			bcVerifiers.add(i, bcVerifier);
			bcVerifier.init();
			bcVerifier.receiveProverMessage();
			bcVerifier.executeVerification();
			bcVerifier.computeChallenge();
			bcVerifier.verifyChallenge();

		}
	}
}
