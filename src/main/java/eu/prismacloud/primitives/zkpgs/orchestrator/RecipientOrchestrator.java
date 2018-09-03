package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphMLProvider;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signature.GSSignatureValidator;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.SigningQCorrectnessVerifier;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;

/** Recipient orchestrator */
public class RecipientOrchestrator {
	private static final String RECIPIENT_GRAPH_FILE = "recipient-infra.graphml";
	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final BigInteger modN;
	private final GroupElement baseS;
	private final GroupElement R_0;
	private final GroupElement baseZ;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private final GroupElement R;
	private final GSRecipient recipient;
	private BigInteger n_1;
	private BigInteger n_2;
	private GSCommitment U;
	private GSSigner signer;
	private BaseCollection encodedBases;
	private BigInteger recipientMSK;
	private GroupElement tildeU;
	private List<String> challengeList;
	private BigInteger cChallenge;
	private Map<URN, BigInteger> responses;
	private BaseCollection encodedBasesCollection;
	private GroupElement A;
	private BigInteger e;
	private BigInteger vPrimePrime;
	private ProofSignature P_2;
	private BigInteger vPrime;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private BaseRepresentation baseR_0;
	private GSSignature gsSignature;

	public RecipientOrchestrator(
			final ExtendedPublicKey extendedPublicKey,
			final KeyGenParameters keyGenParameters,
			final GraphEncodingParameters graphEncodingParameters) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = keyGenParameters;
		this.graphEncodingParameters = graphEncodingParameters;
		this.proofStore = new ProofStore<Object>();
		this.modN = extendedPublicKey.getPublicKey().getModN();
		this.baseS = extendedPublicKey.getPublicKey().getBaseS();
		this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
		this.R = extendedPublicKey.getPublicKey().getBaseR();
		this.R_0 = extendedPublicKey.getPublicKey().getBaseR_0();
		this.recipient = new GSRecipient(extendedPublicKey, keyGenParameters);
	}

	public void round1() throws ProofStoreException {
		encodedBases = new BaseCollectionImpl();

		generateRecipientMSK();

		try {
			createGraphRepresentation();
		} catch (ImportException im) {
			gslog.log(Level.SEVERE, im.getMessage());
		}

		// TODO needs to receive message n_1
		GSMessage msg = recipient.receiveMessage();

		n_1 = (BigInteger) msg.getMessageElements().get(URN.createZkpgsURN("nonces.n_1"));

		vPrime = recipient.generatevPrime();
		proofStore.store("issuing.recipient.vPrime", vPrime);

		U = recipient.commit(encodedBases, vPrime);

		/** TODO generalize commit prover */
		// TODO needs to get access to commitment secrets (recipientGraph)
		// TODO needs to move to the new commitment interface.
		CommitmentProver commitmentProver = new CommitmentProver(U, 0, extendedPublicKey.getPublicKey(), proofStore);

		Map<URN, GroupElement> tildeMap =
				commitmentProver.executeCompoundPreChallengePhase();
		String tildeUURN = URNType.buildURNComponent(URNType.TILDEU, CommitmentProver.class);
		tildeU = tildeMap.get(URN.createZkpgsURN( tildeUURN));

		try {
			cChallenge = computeChallenge();
		} catch (NoSuchAlgorithmException ns) {
			gslog.log(Level.SEVERE, ns.getMessage());
		}

		responses = commitmentProver.executePostChallengePhase(cChallenge);

		//        recipient.createCommitmentProver(U, extendedPublicKey); // TODO Needs access to
		// secrets

		ProofSignature P_1 = createProofSignature(); // TODO Needs to sign n_1

		n_2 = recipient.generateN_2();

		Map<URN, Object> messageElements = new HashMap<>();
		messageElements.put(URN.createZkpgsURN("recipient.U"), U);
		messageElements.put(URN.createZkpgsURN("recipient.P_1"), P_1);
		messageElements.put(URN.createZkpgsURN("recipient.n_2"), n_2);

		recipient.sendMessage(new GSMessage(messageElements));

		/** TODO store context and randomness vPrime */
	}

	public BigInteger computeChallenge() throws NoSuchAlgorithmException {
		challengeList = populateChallengeList();
		return CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
	}

	private List<String> populateChallengeList() {
		/** TODO add context to list of elements in challenge */
		challengeList = new ArrayList<>();
		GSContext gsContext =
				new GSContext(extendedPublicKey);
		List<String> contextList = gsContext.computeChallengeContext();

		challengeList.addAll(contextList);
		challengeList.add(String.valueOf(modN));
		challengeList.add(String.valueOf(baseS));
		challengeList.add(String.valueOf(baseZ));
		challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseR_0()));

		//    BaseIterator baseIterator = encodedBasesCollection.createIterator(BASE.ALL);
		//    for (BaseRepresentation baseRepresentation : baseIterator) {
		//      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
		//    }

		GroupElement commitmentU = U.getCommitmentValue();

		challengeList.add(String.valueOf(commitmentU));
		challengeList.add(String.valueOf(tildeU));
		challengeList.add(String.valueOf(n_1));

		return challengeList;
	}

	private void encodeR_0() {
		baseR_0 = new BaseRepresentation(R_0, recipientMSK, -1, BASE.BASE0);
		encodedBases.add(baseR_0);

		try {
			proofStore.store("bases.R_0", baseR_0);
			proofStore.store("bases.exponent.m_0", recipientMSK);
		} catch (ProofStoreException pse) {
			gslog.log(Level.SEVERE, pse.getMessage());
		}
	}

	private void generateRecipientMSK() {
		recipientMSK = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
	}

	private void createGraphRepresentation() throws ImportException {
		GraphRepresentation graphRepresentation = new GraphRepresentation(extendedPublicKey);
		Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

		GSGraph<GSVertex, GSEdge> gsGraph = GSGraph.createGraph(RECIPIENT_GRAPH_FILE);
		gsGraph.encodeRandomGeoLocationGraph(this.graphEncodingParameters);
		GraphMLProvider.createImporter();

		if (!gsGraph.getGraph().vertexSet().isEmpty()) {
			graphRepresentation.encode(gsGraph);
			encodedBases = graphRepresentation.getEncodedBaseCollection();
		}

		encodeR_0();
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

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.c"), cChallenge);
		hatvPrime = (BigInteger) proofStore.retrieve(hatvPrimeURN);
		hatm_0 = (BigInteger) proofStore.retrieve(hatm_0URN);

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"), hatvPrime);

		// TODO check if hatm_0 is needed inside the proofsignature
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatm_0"), hatm_0);

		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.responses"), responses);

		return new ProofSignature(proofSignatureElements);
	}

	public void round3() throws VerificationException, ProofStoreException {
		GSMessage correctnessMsg = recipient.receiveMessage();
		P_2 = extractMessageElements(correctnessMsg);

		BigInteger v = vPrimePrime.add(vPrime);

		proofStore.store("recipient.vPrimePrime", vPrimePrime);
		proofStore.store("recipient.vPrime", vPrime);

		gslog.info("Validating incoming graph signature.");
		GSSignature signatureCandidate = new GSSignature(extendedPublicKey.getPublicKey(), A, e, v);

		GSSignatureValidator sigmaValidator = new GSSignatureValidator(signatureCandidate, extendedPublicKey.getPublicKey(), proofStore);

		if(!sigmaValidator.verify()) {
			throw new VerificationException("The signature is inconsistent.");
		}

		SigningQVerifierOrchestrator verifyingQOrchestrator = new SigningQVerifierOrchestrator(P_2, signatureCandidate, n_2, extendedPublicKey, proofStore);

		verifyingQOrchestrator.init();
		
		verifyingQOrchestrator.checkLengths();

		cChallenge = verifyingQOrchestrator.computeChallenge();
		
		if(!verifyingQOrchestrator.executeVerification(cChallenge)) {
			throw new VerificationException("Graph signature proof P_2 could not be verified.");
		}
		
		gsSignature = signatureCandidate;

		encodedBasesCollection.add(baseR_0);
		Boolean isValidSignature = gsSignature.verify(extendedPublicKey, encodedBasesCollection);

		if (!isValidSignature) {
			throw new VerificationException("graph signature is not valid");
		}

		gslog.info("recipient: store signature A,e,v");
		proofStore.store("recipient.graphsignature.A", A);
		proofStore.store("recipient.graphsignature.e", e);
		proofStore.store("recipient.graphsignature.v", v);

		gslog.info("recipient: save encoded bases");
		BaseIterator baseRepresentations = encodedBasesCollection.createIterator(BASE.ALL);
		String baseURN = "";
		for (BaseRepresentation baseRepresentation : baseRepresentations) {
			baseURN = createBaseURN(baseRepresentation);
			proofStore.store(baseURN, baseRepresentation);
		}
	}

	private String createBaseURN(BaseRepresentation baseRepresentation) {
		if (BASE.VERTEX == baseRepresentation.getBaseType()) {
			return "encoded.base.vertex.R_i_" + baseRepresentation.getBaseIndex();
		} else if (BASE.EDGE == baseRepresentation.getBaseType()) {
			return "encoded.base.edge.R_i_j_" + baseRepresentation.getBaseIndex();
		}
		return "encoded.base";
	}

	public GSSignature getGraphSignature() {
		return this.gsSignature;
	}

	public BaseCollection getEncodedBasesCollection() {
		return this.encodedBasesCollection;
	}

	private ProofSignature extractMessageElements(GSMessage correctnessMsg) {
		Map<URN, Object> correctnessMessageElements = correctnessMsg.getMessageElements();

		A = (GroupElement) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.A"));
		e = (BigInteger) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.e"));
		vPrimePrime =
				(BigInteger)
				correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.vPrimePrime"));
		P_2 = (ProofSignature) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.P_2"));
		encodedBasesCollection =
				(BaseCollection)
				correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.encoding"));

		return P_2;
	}

	public void close() {
		recipient.close();
	}
}
