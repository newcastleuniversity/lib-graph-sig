package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseCollectionImpl;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;
import eu.prismacloud.primitives.zkpgs.verifier.GSVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.PossessionVerifier;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class VerifierOrchestrator implements IVerifierOrchestrator {

	private ProofSignature P_3;
	private final GSVerifier verifier;
	private final ExtendedPublicKey extendedPublicKey;
	private final ProofStore<Object> proofStore;
	private final KeyGenParameters keyGenParameters;
	private final GraphEncodingParameters graphEncodingParameters;
	private ProofStore<Object> verifierStore = new ProofStore<Object>();
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private GroupElement aPrime;
	private Map<URN, GSCommitment> C_i;
	private BigInteger cChallenge;
	private BigInteger hate;
	private BigInteger hatvPrime;
	private BigInteger hatm_0;
	private List<CommitmentVerifier> commitmentVerifierList;
	private BigInteger tildem_i;
	private BigInteger n_3;
	private List<String> contextList;
	private List<String> challengeList;
	private GroupElement hatZ;
	private BigInteger hatc;
	private BaseCollection baseCollection;

	public VerifierOrchestrator(
			final ExtendedPublicKey extendedPublicKey) {

		this.extendedPublicKey = extendedPublicKey;
		this.proofStore = new ProofStore<Object>();
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.verifier = new GSVerifier(extendedPublicKey);
	}

	@Override
	public void init() throws IOException {
		this.verifier.init();

		n_3 = verifier.computeNonce();
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		messageElements.put(URN.createZkpgsURN("verifier.n_3"), n_3);
		verifier.sendMessage(new GSMessage(messageElements));
	}

	public void receiveProverMessage() throws VerificationException, IOException {
		GSMessage proverMessage = verifier.receiveMessage();
		Map<URN, Object> proverMessageElements = proverMessage.getMessageElements();

		P_3 = (ProofSignature) proverMessageElements.get(URN.createZkpgsURN("prover.P_3"));
		aPrime = (GroupElement) proverMessageElements.get(URN.createZkpgsURN("prover.APrime"));

		C_i = (Map<URN, GSCommitment>) proverMessageElements.get(URN.createZkpgsURN("prover.C_i"));
		Map<URN, Object> proofSignatureElements = P_3.getProofSignatureElements();

		baseCollection = constructBaseCollection(proofSignatureElements);
		
		if (!checkLengths()) {
			/** TODO create a custom exception for lengths or return null */
			throw new VerificationException("Proof signature elements do not have correct length");
		}

		try {
			storePublicValues();
			storeProofSignature(proofSignatureElements);
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}
	}

	@Override
	public boolean checkLengths() {
		int l_hate = keyGenParameters.getL_prime_e() + keyGenParameters.getProofOffset();
		int l_hatvPrime = keyGenParameters.getL_v() + keyGenParameters.getProofOffset();
		int l_m = keyGenParameters.getL_m() + keyGenParameters.getProofOffset() + 1;
		int l_hatr = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

		hate =
				(BigInteger)
				P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.hate"));
		hatvPrime =
				(BigInteger)
				P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.hatvPrime"));
		hatm_0 =
				(BigInteger)
				P_3.getProofSignatureElements().get(URN.createZkpgsURN("proofsignature.P_3.hatm_0"));
		/** TODO check lengths for vertices, edges, and pair-wise different vertex encodings */
		return CryptoUtilsFacade.isInPMRange(hate, l_hate)
				&& CryptoUtilsFacade.isInPMRange(hatvPrime, l_hatvPrime)
				&& CryptoUtilsFacade.isInPMRange(hatm_0, l_m);
	}

	private void storeProofSignature(Map<URN, Object> proofSignatureElements)
			throws ProofStoreException {

		cChallenge =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.c"));
		proofStore.store("verifier.c", cChallenge);

		aPrime =
				(GroupElement) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.APrime"));
		proofStore.store("verifier.APrime", aPrime);

		hate = (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hate"));
		proofStore.store("verifier.hate", hate);

		hatvPrime =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hatvPrime"));
		proofStore.store("verifier.hatvPrime", hatvPrime);

		hatm_0 =
				(BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hatm_0"));
		proofStore.store("verifier.hatm_0", hatm_0);

		/** TODO store vertices from proof signature */
		int baseIndex;
		String hatm_iPath = "possessionprover.responses.vertex.hatm_i_";
		String hatr_iPath = "proving.commitmentprover.responses.hatr_i_";
		String hatm_iURN;
		BigInteger hatm_i;
		BigInteger hatr_i;
		String hatr_iURN;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			baseIndex = vertexBase.getBaseIndex();
			hatm_iURN = hatm_iPath + baseIndex;
			hatm_i =
					(BigInteger)
					proofSignatureElements.get(
							URN.createZkpgsURN("proofsignature.P_3.hatm_i_" + baseIndex));

			proofStore.store(hatm_iPath + baseIndex, hatm_i);
			hatr_iURN = hatr_iPath + baseIndex;
			hatr_i =
					(BigInteger)
					proofSignatureElements.get(
							URN.createZkpgsURN("proofsignature.P_3.hatr_i_" + baseIndex));
			proofStore.store(hatr_iPath + baseIndex, hatr_i);
		}
		/** TODO store edges from proof signature */
		//    String hatm_i_jURN;
		//    String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";
		//    String hatr_iPath = "proving.commitmentprover.responses.hatr_i_";
		//    String hatr_iURN;
		//    BigInteger hatm_i_j;
		//    BigInteger hatr_i;
		//    for (BaseRepresentation edgeBase : edgeIterator) {
		//      baseIndex = edgeBase.getBaseIndex();
		//      hatm_i_jURN = hatm_i_jPath + baseIndex;
		//      hatm_i_j =
		//          (BigInteger)
		//              proofSignatureElements.get(
		//                  URN.createZkpgsURN("proofsignature.P_3.hatm_i_j_" + baseIndex));
		//      Assert.checkBitLength(hatm_i_j, l_m, "hatm_i_j length is not correct");
		//      proofStore.store("verifier.hatm_i_j_" + baseIndex, hatm_i_j);
		//
		//      hatr_iURN = hatr_iPath + baseIndex;
		//      hatr_i =
		//          (BigInteger)
		//              proofSignatureElements.get(
		//                  URN.createZkpgsURN("proofsignature.P_3.hatr_i_" + baseIndex));
		//      Assert.checkBitLength(hatr_i, l_hatr, "hatr_i length is not correct");
		//      proofStore.store("verifier.hatr_i_" + baseIndex, hatr_i);
		//    }
		/** TODO store pair-wise different vertex encodings from the proof signature */
	}

	public void preChallengePhase() throws VerificationException {

		PossessionVerifier possessionVerifier = new PossessionVerifier(baseCollection, extendedPublicKey, proofStore);

		try {

			Map<URN, GroupElement> responses = possessionVerifier.executeCompoundVerification(cChallenge);
			String hatZURN = URNType.buildURNComponent(URNType.HATZ, PossessionVerifier.class);
			hatZ = responses.get(URN.createZkpgsURN(hatZURN));

		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "Could not access the challenge in the ProofStore.", e);
		}
		gslog.info("hatZ : " + hatZ);

		computeCommitmentVerifiers();
	}

	@Override
	public BigInteger computeChallenge() {
		gslog.info("compute challenge ");
		challengeList = populateChallengeList();
		try {
			hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Could not find the hash algorithm.", e);
		}
		return hatc;
	}

	public void verifyChallenge() throws VerificationException {
		if (!cChallenge.equals(hatc)) {
			throw new VerificationException("challenge verification failed");
		}
	}

	private List<String> populateChallengeList() {
		challengeList = new ArrayList<>();

		GSContext gsContext = new GSContext(extendedPublicKey);
		contextList = gsContext.computeChallengeContext();
		challengeList.addAll(contextList);
		challengeList.add(String.valueOf(aPrime));
		challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));

		for (GSCommitment gsCommitment : C_i.values()) {
			challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
		}

		challengeList.add(String.valueOf(hatZ));

		GroupElement commitment;
		String hatC_iURN;
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertex : vertexIterator) {
			hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();
			commitment = (GroupElement) proofStore.retrieve(hatC_iURN);
			challengeList.add(String.valueOf(commitment));
		}

		/** TODO add pair-wise elements for challenge */
		//    for (GroupElement witness : pairWiseWitnesses.values()) {
		//      challengeList.add(String.valueOf(witness));
		//    }
		gslog.info("n3: " + n_3);
		challengeList.add(String.valueOf(n_3));

		return challengeList;
	}

	private void computeCommitmentVerifiers() throws VerificationException {
		CommitmentVerifier commitmentVerifier;
		commitmentVerifierList = new ArrayList<>();

		String witnessRandomnessURN;
		String hatC_iURN;
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertex : vertexIterator) {
			witnessRandomnessURN = "possessionprover.responses.vertex.hatm_i_" + vertex.getBaseIndex();
			BigInteger hatm_i = (BigInteger) proofStore.retrieve(witnessRandomnessURN);

			commitmentVerifier = new CommitmentVerifier(STAGE.VERIFYING, extendedPublicKey, proofStore);

			GroupElement hatCommitment =
					commitmentVerifier.computeWitness(
							cChallenge, vertex);

			commitmentVerifierList.add(commitmentVerifier);
			hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();

			try {
				proofStore.store(hatC_iURN, hatCommitment);
			} catch (Exception e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}
	}

	public void storePublicValues() throws ProofStoreException {
		String ZURN = "verifier.Z";
		String APrimeURN = "verifier.APrime";
		//    String C_iURN = "verifier.C_i";

		verifierStore.store(ZURN, extendedPublicKey.getPublicKey().getBaseZ());
		verifierStore.store(APrimeURN, P_3.get("proofsignature.P_3.APrime"));
		/** TODO check storage of C_i */
		//    verifierStore.store(C_iURN, P_3.get("proofsignature.P_3.C_i"));

		for (Entry<URN, GSCommitment> commitmentEntry : C_i.entrySet()) {
			URN commitmentKey = commitmentEntry.getKey();
			GSCommitment commitment = commitmentEntry.getValue();
			proofStore.save(commitmentKey, commitment);
		}
	}

	@Override
	public void close() throws IOException {
		verifier.close();
	}

	@Override
	public boolean executeVerification(BigInteger cChallenge) {
		// TODO Auto-generated method stub
		return false;
	}
	
	private BaseCollection constructBaseCollection(Map<URN, Object> proofSignatureElements) {
		BaseCollection collection = new BaseCollectionImpl();
		
		String vertexPrefix = "proofsignature.P_3.hatm_i_";
		String edgePrefix = "proofsignature.P_3.hatm_i_j_";
		Iterator<Entry<URN,Object>> candidateEntries = proofSignatureElements.entrySet().iterator();
		while (candidateEntries.hasNext()) {
			Map.Entry<URN, java.lang.Object> entry = 
					(Map.Entry<URN, java.lang.Object>) candidateEntries.next();
			URN key = entry.getKey();
			
			// Retrieving Matching Vertex Bases
			if (key.matchesPrefix(vertexPrefix)) {
				int baseIndex = key.getIndex();
				if (baseIndex < 0) {
					throw new InternalError("The hatm_i values were not indexed correctly.");
				}
				
				BaseRepresentation vertexBase = extendedPublicKey.getVertexBase(baseIndex);
				BigInteger hatm_i = (BigInteger) entry.getValue();
				vertexBase.setExponent(hatm_i);
				collection.add(vertexBase);
			}
			// Retrieving Matching Edge Bases
			if (key.matchesPrefix(edgePrefix)) {
				int baseIndex = key.getIndex();
				if (baseIndex < 0) {
					throw new InternalError("The hatm_i_j values were not indexed correctly.");
				}
				
				BaseRepresentation edgeBase = extendedPublicKey.getEdgeBase(baseIndex);
				BigInteger hatm_i_j = (BigInteger) entry.getValue();
				edgeBase.setExponent(hatm_i_j);
				collection.add(edgeBase);
			}
		}
		

		
		return collection;
	}
}
