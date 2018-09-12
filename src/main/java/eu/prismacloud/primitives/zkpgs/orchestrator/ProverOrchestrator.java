package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.graph.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageError;
import eu.prismacloud.primitives.zkpgs.message.ProofRequest;
import eu.prismacloud.primitives.zkpgs.message.ProofType;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.*;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Orchestrate provers
 */
public class ProverOrchestrator implements IProverOrchestrator {

	private BaseCollection baseCollection;
	private BigInteger n_3;
	private GSSignature graphSignature;
	private GSSignature blindedGraphSignature;
	private GSProver prover;
	private ExtendedPublicKey extendedPublicKey;
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private GroupElement tildeZ;
	private List<PairWiseCommitments> pairWiseCommList;
	private Map<URN, GSCommitment> commitments;
	private Map<URN, GroupElement> pairWiseWitnesses;
	private List<String> challengeList = new ArrayList<String>();
	private ProofStore<Object> proofStore;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private PossessionProver possessionProver;
	private List<CommitmentProver> commitmentProverList;
	private BigInteger cChallenge;
	private List<PairWiseDifferenceProver> pairWiseDifferenceProvers;
	private Map<URN, GSCommitment> indexCommitments;
	private GraphRepresentation graphRepresentation;
	private Vector<Integer> proofIndexes;


	public ProverOrchestrator(final ExtendedPublicKey extendedPublicKey) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.prover = new GSProver(extendedPublicKey, proofStore);

	}

	@Override
	public void init() throws IOException {

		if (graphSignature == null) {
			throw new IOException("The graph signature has not been read, deserialize from file or read from proof-store.");
		}
		if (baseCollection == null) {
			throw new IOException("The graph signature's base collection has not been read, deserialize from file or read from proof-store.");
		}

		if (graphRepresentation == null) {
			throw new IOException("The graph signature's graph representation has not been read, deserialize from file or read from proof-store.");
		}

		this.prover.init();

		GSMessage proofRequestMsg = prover.receiveMessage();

		Map<URN, Object> messageElements = proofRequestMsg.getMessageElements();
		/** TODO create safe URN for proof requests */
		ProofRequest proofRequest = (ProofRequest) messageElements.get(URN.createUnsafeZkpgsURN("proof.request"));

		Assert.notNull(proofRequest, "proof request must not be null");

		if (!proofRequest.getProofType().equals(ProofType.GEOLOCATION_SEPARATION)) {
			sendErrorMessage(MessageError.PROOF_TYPE_NOT_SUPPORTED);
			throw new ProofException("the proof type requested is not supported");
		}

		proofIndexes = proofRequest.getIndexes();

		if ((proofIndexes == null) || proofIndexes.isEmpty()) {
			sendErrorMessage(MessageError.PROOF_ERROR);
			throw new ProofException("Provided wrong number of vertex indexes or none");
		}

		/** TODO send OK message to Verifier */
		prover.sendMessage(new GSMessage());

		indexCommitments = new LinkedHashMap<>();

		// create pair wise commitments
		computePairWiseCommitments();


		GSMessage n_3Msg = prover.receiveMessage();
		messageElements = n_3Msg.getMessageElements();
		n_3 = (BigInteger) messageElements.get(URN.createZkpgsURN("verifier.n_3"));

		try {
			prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
		} catch (ProofStoreException e1) {
			gslog.log(Level.SEVERE, "Commitments not computed correctly; values not found in the ProofStore.", e1.getMessage());
			throw new IOException("Initialization failed. Commitments could not be computed.");
		}
		commitments = prover.getCommitmentMap();
		
		try {
			initPairWiseDifferenceProvers();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "Commitment Pair-Wise Difference Provers not computed correctly; values not found in the ProofStore.", e.getMessage());
			throw new IOException("Initialization failed. Pair-Wise Difference Provers could not be initalized.");
		}

	}

	private void computePairWiseCommitments() {
		Object[] proofIndArray = proofIndexes.toArray();
		for (int i = 0; i < proofIndArray.length; i++) {
			int first = (int) proofIndArray[i];
			for (int j = i + 1; j < proofIndArray.length; j++) {
				int second = (int) proofIndArray[j];
				computeIndexesCommitments(first);
				computeIndexesCommitments(second);
//				gslog.info("(" + first + ", " + second + ')');
			}
		}
	}

	private Map<URN, Object> createErrorMessage(MessageError messageError) {
		Map<URN, Object> errorMessageElements = new HashMap<>();
		errorMessageElements.put(URN.createUnsafeZkpgsURN("message.error"), messageError);
		return errorMessageElements;
	}

	private void initPairWiseDifferenceProvers() throws IOException, ProofStoreException {
		List<GSCommitment> commitmentList = new ArrayList<GSCommitment>(indexCommitments.values());
		PairWiseCommitments pairWiseCommitments;

		pairWiseCommList = new ArrayList<>();
		Object[] commArray = commitmentList.toArray();
		// create pair wise commitments from the commitment list
		for (int i = 0; i < commArray.length; i++) {
			GSCommitment C_i = (GSCommitment) commArray[i];
			for (int j = i + 1; j < commArray.length; j++) {
				GSCommitment C_j = (GSCommitment) commArray[j];
				pairWiseCommitments = new PairWiseCommitments(C_i, C_j);
				pairWiseCommList.add(pairWiseCommitments);
			}
		}

//		gslog.info("pairWiseCommList: " + pairWiseCommList.size());

		pairWiseDifferenceProvers = new ArrayList<>();
		int pairWiseProverIndex = 0;
		for (PairWiseCommitments pwCommitments : pairWiseCommList) {
			PairWiseDifferenceProver pairWiseDifferenceProver = new PairWiseDifferenceProver(pwCommitments.getC_i(), pwCommitments.getC_j(), pairWiseProverIndex, extendedPublicKey, proofStore);
			pairWiseDifferenceProvers.add(pairWiseDifferenceProver);
			
			try {
				pairWiseDifferenceProver.executePrecomputation();
			} catch (IllegalArgumentException ie) {
				gslog.log(Level.SEVERE, "Messages are not co-prime. Bezout identity factors for "
						+ "pair-wise difference proof cannot be established.", ie.getMessage());
				sendErrorMessage(MessageError.PROOF_ERROR);
				throw ie;
			}
			pairWiseProverIndex++;
		}
	}

	private void sendErrorMessage(MessageError messageError) throws IOException {
		Map<URN, Object> errorMessageElements = createErrorMessage(messageError);
		GSMessage errorMsg = new GSMessage(errorMessageElements);
		prover.sendMessage(errorMsg);
	}

	private void computeIndexesCommitments(int queriedId) {
		GSVertex vertex = graphRepresentation.getVertexById(String.valueOf(queriedId));

		// 2. Lookup base index of the vertex in this graph encoding
		int baseIndex = graphRepresentation.getBaseIndexOfVertex(vertex);

		// 3. Obtain the base.
		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		BaseRepresentation base = vertexIterator.getBaseByIndex(baseIndex);

		if (base == null) {
			throw new IllegalArgumentException("base does not exist for corresponding index");
		} else {
			GSCommitment comm = GSCommitment.createCommitment(base.getExponent(), extendedPublicKey);
			/** TODO add safe URN for proof commitments */
			indexCommitments.put(URN.createUnsafeZkpgsURN("proof.commitments.C_i_" + base.getBaseIndex()), comm);
		}

	}


	@Override
	public void executePreChallengePhase() {
		this.blindedGraphSignature = graphSignature.blind();

		try {
			storeBlindedGS();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "Blinded graph signature could not be stored.", e);
		}

		try {
			computeTildeZ();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, "Blinded graph signature could not be stored.", e);
		}


		try {
			computeCommitmentProvers();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}

		computePairWiseProvers(pairWiseDifferenceProvers);
	}

	private void storeBlindedGS() throws ProofStoreException {
//		String commitmentsURN = "prover.commitments.C_iMap";
//		proofStore.store(commitmentsURN, commitments);

		String blindedGSURN = "prover.blindedgs.signature.sigma";
		proofStore.store(blindedGSURN, this.blindedGraphSignature);

		String APrimeURN = "prover.blindedgs.signature.APrime";
		proofStore.store(APrimeURN, this.blindedGraphSignature.getA());

		String ePrimeURN = "prover.blindedgs.signature.ePrime";
		proofStore.store(ePrimeURN, this.blindedGraphSignature.getEPrime());

		String vPrimeURN = "prover.blindedgs.signature.vPrime";
		proofStore.store(vPrimeURN, this.blindedGraphSignature.getV());
	}

	@Override
	public ProofSignature createProofSignature() {
		String hateURN = "possessionprover.responses.hate";
		BigInteger hate = (BigInteger) proofStore.retrieve(hateURN);
		String hatvPrimeURN = "possessionprover.responses.hatvPrime";
		BigInteger hatvPrime = (BigInteger) proofStore.retrieve(hatvPrimeURN);
		BigInteger hatm_0 = (BigInteger) proofStore.get(URNType.buildURN(URNType.HATM0, PossessionProver.class));

		Map<URN, Object> proofSignatureElements = new HashMap<>();
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.challenge.c"), cChallenge);
		proofSignatureElements.put(
				URN.createZkpgsURN("proofsignature.P_3.signature.APrime"), blindedGraphSignature.getA());
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.responses.hate"), hate);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.responses.hatvPrime"), hatvPrime);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.responses.hatm_0"), hatm_0);

		int baseIndex;
		String hatm_iPath = "possessionprover.responses.vertex.hatm_i_";
		String hatm_iURN;
		String hatr_iPath = "commitmentprover.responses.vertex.hatr_i_";
		String hatr_iURN;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			baseIndex = vertexBase.getBaseIndex();
			hatm_iURN = hatm_iPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.responses.hatm_i_" + baseIndex),
					proofStore.retrieve(hatm_iURN));
			hatr_iURN = hatr_iPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.responses.hatr_i_" + baseIndex),
					proofStore.retrieve(hatr_iURN));
		}

		String hatm_i_jURN;
		String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";
		String hatr_i_jPath = "commitmentprover.responses.edge.hatr_i_j_";

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			baseIndex = edgeBase.getBaseIndex();
			hatm_i_jURN = hatm_i_jPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.responses.hatm_i_j_" + baseIndex),
					proofStore.retrieve(hatm_i_jURN));

//            String hatr_i_jURN = hatr_i_jPath + baseIndex;
//                       hatr_i_j =
//                               (BigInteger)
//                                       proofSignatureElements.put(
//                                               URN.createZkpgsURN("proofsignature.P_3.responses.hatr_i_j_" + baseIndex),
//                       proofStore.retrieve(hatr_i_jURN));
		}


		for (PairWiseDifferenceProver pwDifferenceProver : pairWiseDifferenceProvers) {
			int pwProverIndex = pwDifferenceProver.getIndex();
			proofSignatureElements.put(URN.createUnsafeZkpgsURN("proofsignature.P_3.hata_Bari_Barj_" + pwProverIndex), pwDifferenceProver.getHata_BariBarj());

			proofSignatureElements.put(URN.createUnsafeZkpgsURN("proofsignature.P_3.hatb_Bari_Barj_" + pwProverIndex), pwDifferenceProver.getHatb_BariBarj());

			proofSignatureElements.put(URN.createUnsafeZkpgsURN("proofsignature.P_3.hatr_Bari_Barj_" + pwProverIndex), pwDifferenceProver.getHatr_BariBarj());
			proofSignatureElements.put(URN.createUnsafeZkpgsURN("proofsignature.P_3.C_Bari_C_Barj_" + pwProverIndex), pairWiseCommList.get(pwProverIndex));

		}

		return new ProofSignature(proofSignatureElements);
	}

	@Override
	public BigInteger computeChallenge() {
		challengeList = populateChallengeList();
		BigInteger c = null;
		try {
			c = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Fiat-Shamir challenge could not be computed.", e);
		}
		return c;
	}

	@Override
	public void executePostChallengePhase(BigInteger cChallenge) throws IOException {
		this.cChallenge = cChallenge;

		Map<URN, BigInteger> responses;
		try {
			responses = possessionProver.executePostChallengePhase(cChallenge);
		} catch (ProofStoreException e1) {
			gslog.log(Level.SEVERE, "Could not access the ProofStore.", e1);
			return;
		}

		Map<URN, BigInteger> response;
		for (CommitmentProver commitmentProver : commitmentProverList) {
			try {
				response = commitmentProver.executePostChallengePhase(cChallenge);
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, "Could not access the ProofStore.", e);
				return;
			}

			responses.putAll(response);
		}

		for (PairWiseDifferenceProver pwProver : pairWiseDifferenceProvers) {

			try {
				response = pwProver.executePostChallengePhase(cChallenge);
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, "Could not access the ProofStore.", e);
				return;
			}

			responses.putAll(response);
		}

		ProofSignature P_3 = createProofSignature();

		Map<URN, Object> messageElements = new HashMap<>();
		messageElements.put(URN.createZkpgsURN("prover.P_3"), P_3);

		// add public values
		messageElements.put(URN.createZkpgsURN("prover.APrime"), blindedGraphSignature.getA());
		messageElements.put(URN.createZkpgsURN("prover.commitments.C_iMap"), commitments);

		prover.sendMessage(new GSMessage(messageElements));
	}

	private List<String> populateChallengeList() {
		GSContext gsContext = new GSContext(extendedPublicKey);
		List<String> contextList = gsContext.computeChallengeContext();
		challengeList.addAll(contextList);
		challengeList.add(String.valueOf(blindedGraphSignature.getA()));
		challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));
		for (GSCommitment gsCommitment : commitments.values()) {
			challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
		}

		challengeList.add(String.valueOf(tildeZ));

		String tildeC_iURN;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertex : vertexIterator) {
			tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();
			GroupElement commitment = (GroupElement) proofStore.retrieve(tildeC_iURN);
			challengeList.add(String.valueOf(commitment));

		}

		for (GroupElement witness : pairWiseWitnesses.values()) {
			challengeList.add(String.valueOf(witness));
		}

		challengeList.add(String.valueOf(n_3));
		Collections.sort(challengeList);
		return challengeList;
	}

	private void computePairWiseProvers(List<PairWiseDifferenceProver> pairWiseDifferenceProvers) {
		pairWiseWitnesses = new LinkedHashMap<URN, GroupElement>();

		for (PairWiseDifferenceProver differenceProver : pairWiseDifferenceProvers) {

			try {
				pairWiseWitnesses.putAll(differenceProver.executeCompoundPreChallengePhase());
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, "Could not access the ProofStore.", e);
				return;
			}

		}
	}

	private void computeCommitmentProvers() throws ProofStoreException {
		CommitmentProver commitmentProver;
		commitmentProverList = new ArrayList<>();

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertex : vertexIterator) {
			String commURN = "prover.commitments.C_i_" + vertex.getBaseIndex();
			GSCommitment com = commitments.get(URN.createZkpgsURN(commURN));
			Assert.notNull(com, "Commitment submitted to CommitmentProver must not be null.");

			commitmentProver = new CommitmentProver(com, vertex.getBaseIndex(), extendedPublicKey.getPublicKey(), proofStore);

			GroupElement tildeCommitment = commitmentProver.executePreChallengePhase();

			commitmentProverList.add(commitmentProver);

			String tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();

			try {
				proofStore.store(tildeC_iURN, tildeCommitment);
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
		}
	}

	private void computeTildeZ() throws ProofStoreException {
		possessionProver = new PossessionProver(blindedGraphSignature, extendedPublicKey, proofStore);

		Map<URN, GroupElement> tildeMap = possessionProver.executeCompoundPreChallengePhase();
		tildeZ = tildeMap.get(URN.createZkpgsURN(possessionProver.getProverURN(URNType.TILDEZ)));
	}

	public void constructSignatureFromProofStore() throws ProofStoreException {
		GroupElement A = (GroupElement) proofStore.retrieve("graphsignature.A");
		BigInteger e = (BigInteger) proofStore.retrieve("graphsignature.e");
		BigInteger v = (BigInteger) proofStore.retrieve("graphsignature.v");
		this.graphSignature = new GSSignature(extendedPublicKey.getPublicKey(), A, e, v);
		this.baseCollection = (BaseCollection) proofStore.retrieve("encoded.bases");
		this.graphRepresentation = graphSignature.getGraphRepresentation();
	}

	public void readSignature(String filename) throws IOException, ClassNotFoundException {

		FilePersistenceUtil persistenceUtil = new FilePersistenceUtil();
		this.graphSignature = (GSSignature) persistenceUtil.read(filename);
		this.baseCollection = this.graphSignature.getEncodedBases();
		this.graphRepresentation = this.graphSignature.getGraphRepresentation();
	}

	@Override
	public void close() throws IOException {
		prover.close();
	}


}
