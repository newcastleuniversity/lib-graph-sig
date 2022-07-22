package uk.ac.ncl.cascade.binding;

import org.jgrapht.io.ImportException;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.encoding.IGraphEncoding;
import uk.ac.ncl.cascade.zkpgs.exception.EncodingException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedKeyPair;
import uk.ac.ncl.cascade.zkpgs.keys.SignerPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.MessageGatewayProxy;
import uk.ac.ncl.cascade.zkpgs.orchestrator.SignerOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigner;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import static uk.ac.ncl.cascade.zkpgs.DefaultValues.*;

/**
 * Signer orchestrator for issuing a graph signature encoding prime representatives derived from platforms in a network after successfully executing proof of possession for binding and device credentials.
 */
public class SignerOrchestratorPoB {

	private final String graphFilename;
	private final ExtendedKeyPair extendedKeyPair;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final IGraphEncoding graphEncoding;
	private final ProofStore<Object> proofStore;
	private final GSSigner signer;
	private final SignerPublicKey signerPublicKey;
	private final int bindingCredentialsNo;
	private final IMessageGateway globalMessageGateway;
	private MessageGatewayProxy messageGateway;

	public SignerOrchestratorPoB(final String graphFilename,
								 final ExtendedKeyPair extendedKeyPair, final IMessageGateway messageGateway,final int bindingCredentialsNo) {
		this.graphFilename = graphFilename;
		this.extendedKeyPair = extendedKeyPair;
		this.bindingCredentialsNo = bindingCredentialsNo;
		this.keyGenParameters = this.extendedKeyPair.getKeyGenParameters();
		this.graphEncodingParameters = this.extendedKeyPair.getGraphEncodingParameters();
		this.globalMessageGateway = messageGateway;
		this.graphEncoding = extendedKeyPair.getEncoding();
		this.proofStore = new ProofStore<Object>();
		this.signer = new GSSigner(extendedKeyPair, messageGateway);
		this.signerPublicKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
	}


	public SignerOrchestratorPoB(final String graphFilename,
							  final ExtendedKeyPair extendedKeyPair, final IGraphEncoding encoding, final IMessageGateway messageGateway, final int bindingCredentialsNo) {
		this.graphFilename = graphFilename;
		this.extendedKeyPair = extendedKeyPair;
		this.graphEncoding = encoding;
		this.keyGenParameters = this.extendedKeyPair.getKeyGenParameters();
		this.graphEncodingParameters = this.extendedKeyPair.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.signer = new GSSigner(extendedKeyPair, messageGateway);
		this.signerPublicKey = extendedKeyPair.getExtendedPublicKey().getPublicKey();
		this.bindingCredentialsNo = bindingCredentialsNo;
		this.globalMessageGateway = messageGateway;
	}

	public void executePoPBinding() throws VerificationException, IOException, ProofStoreException, NoSuchAlgorithmException, ClassNotFoundException {
		
		VerifierOrchestratorMultiBC multiverifier = new VerifierOrchestratorMultiBC(this.extendedKeyPair.getExtendedPublicKey(), bindingCredentialsNo);
			List<IMessageGateway> messageGateways = new ArrayList<IMessageGateway>();

			System.out.println("Thread: " + Thread.currentThread().getName());
			for (int i = 0; i < bindingCredentialsNo; i++) {
				messageGateway = new MessageGatewayProxy(CLIENT, SERVER_ADDR, PORT + i);
				messageGateways.add(i, messageGateway);
			}
			multiverifier.executeVerifiers(messageGateways);
	}

	public void executeGraphSignatureIssuing() throws IOException, EncodingException, VerificationException, ProofStoreException, NoSuchAlgorithmException, ImportException {
		SignerOrchestrator signer = new SignerOrchestrator(extendedKeyPair, globalMessageGateway);

		signer.init();
		signer.round0();
		signer.round2();
		signer.close();
		
	}
	
}
