package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.prover.GSProver;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * Establishes an orchestrator of provers for multiple proofs of possession of binding credentials.
 */
public class ProverOrchestratorMultiBC {

	private final ExtendedPublicKey extendedPublicKey;
	private final int bindingCredentialsNo;
	private final Logger gslog = GSLoggerConfiguration.getGSlog();

	public ProverOrchestratorMultiBC(final ExtendedPublicKey extendedPublicKey, final int bindingCredentialsNo) {
		this.extendedPublicKey = extendedPublicKey;
		this.bindingCredentialsNo = bindingCredentialsNo;
	}



	public void executeProvers(List<IMessageGateway> messageGateways) throws IOException, ClassNotFoundException, ProofStoreException, NoSuchAlgorithmException {

		List<String> fileNames = new ArrayList<String>();
		for (int i = 0; i < bindingCredentialsNo; i++) {
			fileNames.add("vertexCred_" + i + ".ser");
		}

		ProverOrchestratorBC bcProver;

		for (int i = 0; i < bindingCredentialsNo; i++) {
			gslog.info("iteration: " + i);
			bcProver = new ProverOrchestratorBC(this.extendedPublicKey, messageGateways.get(i));

			bcProver.readSignature("vertexCred_" + i + ".ser");
			bcProver.init();
			bcProver.executePreChallengePhase();
			BigInteger cChallenge = bcProver.computeChallenge();
			bcProver.executePostChallengePhase(cChallenge);

		}
	}
}