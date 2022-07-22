package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.orchestrator.RecipientOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.recipient.GSRecipient;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static uk.ac.ncl.cascade.topographia.TopographiaDefaultOptionValues.DEF_GSSIGNATURE;

/**
 * The recipient part of the issuing protocol for the proof of binding computing graph signature for the platforms with binding credentials.
 */
public class RecipientOrchestratorPoB {
	private final String graphFilename;
	private final ExtendedPublicKey extendedPublicKey;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final IMessageGateway messageGateway;
	private final ProofStore<Object> proofStore;

	public RecipientOrchestratorPoB(final String graphFilename,
									final ExtendedPublicKey extendedPublicKey,
									final IMessageGateway messageGateway) {
		this.graphFilename = graphFilename;
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.messageGateway = messageGateway;
		this.proofStore = new ProofStore<Object>();
	}

	public RecipientOrchestratorPoB(final ExtendedPublicKey extendedPublicKey, final IMessageGateway messageGateway) {
		this(DefaultValues.RECIPIENT_GRAPH_FILE, extendedPublicKey, messageGateway);
	}

	public void executeGraphSignatureIssuing() throws IOException, EncodingException, VerificationException, ProofStoreException, NoSuchAlgorithmException {
		RecipientOrchestrator recipient = new RecipientOrchestrator(graphFilename, extendedPublicKey, messageGateway);
		recipient.init();
		recipient.round1();
		recipient.round3();
		recipient.close();
		recipient.serializeFinalSignature(DEF_GSSIGNATURE);
	}


}
