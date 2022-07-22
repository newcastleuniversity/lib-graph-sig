package uk.ac.ncl.cascade.binding;

import uk.ac.ncl.cascade.zkpgs.BaseRepresentation;
import uk.ac.ncl.cascade.zkpgs.BaseRepresentation.BASE;
import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;
import uk.ac.ncl.cascade.zkpgs.context.GSContext;
import uk.ac.ncl.cascade.zkpgs.exception.ProofException;
import uk.ac.ncl.cascade.zkpgs.exception.ProofStoreException;
import uk.ac.ncl.cascade.zkpgs.graph.GSVertex;
import uk.ac.ncl.cascade.zkpgs.graph.GraphRepresentation;
import uk.ac.ncl.cascade.zkpgs.keys.ExtendedPublicKey;
import uk.ac.ncl.cascade.zkpgs.message.*;
import uk.ac.ncl.cascade.zkpgs.orchestrator.IProverOrchestrator;
import uk.ac.ncl.cascade.zkpgs.parameters.GraphEncodingParameters;
import uk.ac.ncl.cascade.zkpgs.parameters.KeyGenParameters;
import uk.ac.ncl.cascade.zkpgs.prover.*;
import uk.ac.ncl.cascade.zkpgs.signature.GSSignature;
import uk.ac.ncl.cascade.zkpgs.store.ProofStore;
import uk.ac.ncl.cascade.zkpgs.store.URN;
import uk.ac.ncl.cascade.zkpgs.store.URNType;
import uk.ac.ncl.cascade.zkpgs.util.*;
import uk.ac.ncl.cascade.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Orchestrate provers
 */
public class ProverOrchestratorPoB implements IProverOrchestrator {

	private BaseCollection baseCollection;
	private BigInteger n_3;
	private GSSignature graphSignature;
	private GSSignature blindedGraphSignature;
	private GSProver prover;
	private final ExtendedPublicKey extendedPublicKey;
	private KeyGenParameters keyGenParameters;
	private GraphEncodingParameters graphEncodingParameters;
	private GroupElement tildeZ;
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


	public ProverOrchestratorPoB(final ExtendedPublicKey extendedPublicKey, final IMessageGateway messageGateway) {
		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.prover = new GSProver(extendedPublicKey, proofStore, messageGateway);
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
		Map<URN, Object> messageElements = new HashMap<URN, Object>();
		GSMessage n_3Msg = prover.receiveMessage();
		messageElements = n_3Msg.getMessageElements();
		n_3 = (BigInteger) messageElements.get(URN.createZkpgsURN("verifier.n_3"));
		Assert.notNull(n_3, "n_3 must not be null");

		try {
			prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
		} catch (ProofStoreException e1) {
			gslog.log(Level.SEVERE, "Commitments not computed correctly; values not found in the ProofStore.", e1.getMessage());
			throw new IOException("Initialization failed. Commitments could not be computed.");
		}
		commitments = prover.getCommitmentMap();
	}


	private Map<URN, Object> createErrorMessage(MessageError messageError) {
		Map<URN, Object> errorMessageElements = new HashMap<>();
		errorMessageElements.put(URN.createUnsafeZkpgsURN("message.error"), messageError);
		return errorMessageElements;
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


		challengeList.add(String.valueOf(n_3));
		Collections.sort(challengeList);
		return challengeList;
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
