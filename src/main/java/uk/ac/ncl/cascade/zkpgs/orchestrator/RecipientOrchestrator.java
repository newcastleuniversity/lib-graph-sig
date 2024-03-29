package uk.ac.ncl.cascade.zkpgs.orchestrator;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.DefaultValues;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.exception.VerificationException;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.GSMessage;
import uk.ac.ncl.cascade.zkpgs.message.IMessageGateway;
import uk.ac.ncl.cascade.zkpgs.message.IMessagePartner;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.IssuingCommitmentProver;
import uk.ac.ncl.cascade.zkpgs.prover.ProofSignature;
import uk.ac.ncl.cascade.zkpgs.recipient.GSRecipient;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignatureValidator;
import uk.ac.ncl.cascade.zkpgs.signer.GSSigner;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.util.Assert;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollection;
import uk.ac.ncl.cascade.zkpgs.util.BaseCollectionImpl;
import uk.ac.ncl.cascade.zkpgs.util.BaseIterator;
import uk.ac.ncl.cascade.zkpgs.util.CryptoUtilsFacade;
import uk.ac.ncl.cascade.zkpgs.util.FilePersistenceUtil;
import uk.ac.ncl.cascade.zkpgs.util.GSLoggerConfiguration;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Recipient orchestrator */
public class RecipientOrchestrator implements IMessagePartner {

	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final BigInteger modN;
	private final GroupElement baseS;
	private final GroupElement R_0;
	private final GroupElement baseZ;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final GSRecipient recipient;
	private BigInteger n_1;
	private BigInteger n_2;
	private GSCommitment U;
	private GSSigner signer;
	private BaseCollection committedBases;
	private BaseCollection signedBases;
	private BigInteger recipientMSK;
	private GroupElement tildeU;
	private List<String> challengeList;
	private BigInteger cChallenge;
	private BigInteger cPrime;
	private Map<URN, BigInteger> responses;
	private GroupElement A;
	private BigInteger e;
	private BigInteger vPrimePrime;
	private ProofSignature P_2;
	private BigInteger vPrime;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private GSSignature gsSignature;
	private final GroupElement R;
	private BaseRepresentation baseR_0;
	private boolean encodingFinalized = false;
	private GraphRepresentation signedGraphRepresentation;

	public RecipientOrchestrator(final String graphFilename,
								 final ExtendedPublicKey extendedPublicKey,
								 final IMessageGateway messageGateway) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.modN = extendedPublicKey.getPublicKey().getModN();
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();
		this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
		this.R = extendedPublicKey.getPublicKey().getBaseR();
		this.R_0 = extendedPublicKey.getPublicKey().getBaseR_0();
		this.recipient = new GSRecipient(extendedPublicKey, messageGateway);
	}

	public RecipientOrchestrator(final ExtendedPublicKey extendedPublicKey, final IMessageGateway messageGateway) {
		this(DefaultValues.RECIPIENT_GRAPH_FILE, extendedPublicKey, messageGateway);
	}

	@Override
	public void init() throws IOException {
		this.recipient.init();

		committedBases = new BaseCollectionImpl();

		generateRecipientMSK();

		encodeR_0(committedBases);
		try {
			proofStore.store("bases.baseR_0", baseR_0);
			proofStore.store("bases.exponent.m_0", recipientMSK);
		} catch (ProofStoreException pse) {
			gslog.log(Level.SEVERE, pse.getMessage());
		}

		//		try {
		//			if (graphFilename != null) { 
		//				createGraphRepresentation(graphFilename);
		//			}
		//		} catch (ImportException im) {
		//			throw new IOException(im.getMessage());
		//		} catch (EncodingException e) {
		//			throw new IOException(e.getMessage());
		//		}
	}



	public void round1() throws ProofStoreException, IOException, NoSuchAlgorithmException {

		GSMessage msg = recipient.receiveMessage();

		n_1 = (BigInteger) msg.getMessageElements().get(URN.createZkpgsURN("nonces.n_1"));

		// Establishing the commitment
		vPrime = recipient.generatevPrime();
		proofStore.store("issuing.recipient.vPrime", vPrime);

		U = recipient.commit(committedBases, vPrime);

		// Starting the representation proof of the commitment
		IssuingCommitmentProver commitmentProver = new IssuingCommitmentProver(U, 
				extendedPublicKey.getPublicKey(), proofStore);

		tildeU = commitmentProver.executePreChallengePhase();

		cChallenge = computeChallenge();

		responses = commitmentProver.executePostChallengePhase(cChallenge);

		// Finalizing the proof signature.
		ProofSignature P_1 = createProofSignature(); 

		n_2 = recipient.generateN_2();


		// Create a clone of the commitment which is restricted to its public values.
		// To be sent to the Signer.
		GSCommitment commitmentUtoBeSent = U.publicClone();

		Map<URN, Object> messageElements = new HashMap<>();
		messageElements.put(URN.createZkpgsURN("recipient.U"), commitmentUtoBeSent);
		messageElements.put(URN.createZkpgsURN("recipient.P_1"), P_1);
		messageElements.put(URN.createZkpgsURN("recipient.n_2"), n_2);

		recipient.sendMessage(new GSMessage(messageElements));
	}




	public void round3() throws VerificationException, ProofStoreException, IOException {
		GSMessage correctnessMsg = recipient.receiveMessage();
		P_2 = extractMessageElements(correctnessMsg);

		BigInteger v = vPrimePrime.add(vPrime);

		proofStore.store("recipient.vPrimePrime", vPrimePrime);

		/* The encodedBases of P_2 only includes the bases provided by the issuer.
		 * Consequently, the bases still need to be extended with at least the
		 * master secret key msk on base R_0 and the Recipient-provided graph.
		 */
		encodeRecipientCommitment();

		GSSignature signatureCandidate = new GSSignature(extendedPublicKey.getPublicKey(), A, e, v);
		
		// Complementing the signature with its auxiliary data.
		Assert.notNull(signedBases, "The signed bases were found null");
		signatureCandidate.setEncodedBases(signedBases);
		
		Assert.notNull(signedGraphRepresentation, "The signed graph representation was found null");
		signatureCandidate.setGraphRepresentation(signedGraphRepresentation);

		GSSignatureValidator sigmaValidator = new GSSignatureValidator(signatureCandidate, extendedPublicKey.getPublicKey(), proofStore);

		GroupElement Q = sigmaValidator.computeQ();
		proofStore.store("issuing.recipient.Q", Q);


		if(!sigmaValidator.verify()) {
			throw new VerificationException("The signature is inconsistent.");
		}

		SigningQVerifierOrchestrator verifyingQOrchestrator = new SigningQVerifierOrchestrator(P_2, signatureCandidate, n_2, extendedPublicKey, proofStore);

		verifyingQOrchestrator.init();

		verifyingQOrchestrator.checkLengths();

		cPrime = (BigInteger) P_2.get("P_2.cPrime");

		try {
			if(!verifyingQOrchestrator.executeVerification(cPrime)) {
				throw new VerificationException("Graph signature proof P_2 could not be verified.");
			}
		} catch (NoSuchAlgorithmException e1) {
			throw new VerificationException("Graph signature proof P_2 could not be verified.", e1);
		}

		gsSignature = signatureCandidate;

		Boolean isValidSignature = gsSignature.verify(extendedPublicKey, signedBases);

		if (!isValidSignature) {
			throw new VerificationException("Graph signature is not valid");
		}

		proofStore.store("recipient.graphsignature.A", A);
		proofStore.store("recipient.graphsignature.e", e);
		proofStore.store("recipient.graphsignature.v", v);

		BaseIterator baseRepresentations = signedBases.createIterator(BASE.ALL);
		String baseURN = "";
		for (BaseRepresentation baseRepresentation : baseRepresentations) {
			baseURN = createBaseURN(baseRepresentation);
			proofStore.store(baseURN, baseRepresentation);
		}
	}






	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		return CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
	}

	private List<String> populateChallengeList() {
		challengeList = new ArrayList<>();
		GSContext gsContext = new GSContext(extendedPublicKey);
		List<String> contextList = gsContext.computeChallengeContext();

		challengeList.addAll(contextList);

		challengeList.add(String.valueOf(U.getCommitmentValue()));
		challengeList.add(String.valueOf(tildeU));
		challengeList.add(String.valueOf(n_1));

		return challengeList;
	}

	private void encodeR_0(BaseCollection targetCollection) {
		baseR_0 = new BaseRepresentation(R_0, recipientMSK, -1, BASE.BASE0);
		baseR_0.setExponent(this.recipientMSK);
		targetCollection.add(baseR_0);
	}

	private void generateRecipientMSK() {
		recipientMSK = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
	}


	/**
	 * Create proof signature proof signature.
	 *
	 * @return the proof signature
	 */
	public ProofSignature createProofSignature() {
		Map<URN, Object> proofSignatureElements = new HashMap<>();
		BigInteger hatvPrime;
		BigInteger hatm_0;
		String hatvPrimeURN = "issuing.commitmentprover.responses.hatvPrime";
		String hatm_0URN = "issuing.commitmentprover.responses.hatm_0";

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.challenge.c"), cChallenge);
		hatvPrime = (BigInteger) proofStore.retrieve(hatvPrimeURN);
		hatm_0 = (BigInteger) proofStore.retrieve(hatm_0URN);

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.responses.hatvPrime"), hatvPrime);

		// TODO check if hatm_0 is needed inside the proofsignature
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.responses.hatm_0"), hatm_0);

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.responses.hatMap"), responses);

		return new ProofSignature(proofSignatureElements);
	}



	private void encodeRecipientCommitment() {
		encodeR_0(signedBases);

		encodingFinalized = true;
	}

	private String createBaseURN(BaseRepresentation baseRepresentation) {
		if (BASE.VERTEX == baseRepresentation.getBaseType()) {
			return "encoded.base.vertex.baseR_i_" + baseRepresentation.getBaseIndex();
		} else if (BASE.EDGE == baseRepresentation.getBaseType()) {
			return "encoded.base.edge.baseR_i_j_" + baseRepresentation.getBaseIndex();
		} else if (BASE.BASE0 == baseRepresentation.getBaseType()) {
			return "encoded.base.baseR_0";
		}
		return "encoded.base";
	}

	public GSSignature getGraphSignature() {
		return this.gsSignature;
	}

	public BaseCollection getEncodedBases() {
		if (!encodingFinalized || signedBases == null) 
			throw new IllegalStateException("The encoded bases have not been completely finalized, yet.");
		return this.signedBases;
	}

	private ProofSignature extractMessageElements(GSMessage correctnessMsg) {
		Map<URN, Object> correctnessMessageElements = correctnessMsg.getMessageElements();

		A = (GroupElement) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.A"));
		e = (BigInteger) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.e"));
		vPrimePrime =
				(BigInteger)
				correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.vPrimePrime"));
		P_2 = (ProofSignature) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.P_2"));
		signedBases =
				(BaseCollection)
				correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.encoding.baseMap"));
		
		signedGraphRepresentation = (GraphRepresentation) correctnessMessageElements.get(
				URN.createZkpgsURN("proofsignature.encoding.GR"));

		return P_2;
	}

	public void serializeFinalSignature(String filename) throws IOException, NullPointerException {
		Assert.notNull(gsSignature, "The signature was null.");

		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();

		persistenceUtil.write(gsSignature, filename);
	}

	@Override
	public void close() throws IOException {
		recipient.close();
	}
}
