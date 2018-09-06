package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.*;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.*;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
	private Map<URN, BaseRepresentation> vertices;
	private Map<URN, BaseRepresentation> edges;
	private Map<URN, GSCommitment> tildeC_i;
	private Map<URN, BigInteger> hatV;
	private List<PairWiseCommitments> pairWiseVertices;
	private Map<URN, GSCommitment> commitments;
	private BigInteger r_i;
	private GSCommitment commitment;
	private Map<URN, BigInteger> edgeWitnesses;
	private Map<URN, BigInteger> vertexWitnesses;
	private Map<URN, GroupElement> pairWiseWitnesses;
	private List<String> challengeList = new ArrayList<String>();
	private GroupElement tildeR_BariBarj;
	private BigInteger c;
	private ProofStore<Object> proofStore;
	private Map<URN, BaseRepresentation> encodedBases;
	private Map<URN, BaseRepresentation> encodedVertexBases;
	private Logger gslog = GSLoggerConfiguration.getGSlog();
	private List<String> contextList;
	private BigInteger cChallenge;
	private PossessionProver possessionProver;
	private List<CommitmentProver> commitmentProverList;
	private Map<URN, BigInteger> response;
	private Map<URN, BigInteger> responses;

	public ProverOrchestrator(
			final ExtendedPublicKey extendedPublicKey) {

		this.extendedPublicKey = extendedPublicKey;
		this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
		this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
		this.proofStore = new ProofStore<Object>();
		this.prover = new GSProver(extendedPublicKey, proofStore);
	}

	@Override
	public void init() throws IOException {
		this.prover.init();

		GroupElement A = (GroupElement) proofStore.retrieve("graphsignature.A");
		BigInteger e = (BigInteger) proofStore.retrieve("graphsignature.e");
		BigInteger v = (BigInteger) proofStore.retrieve("graphsignature.v");
		gslog.info("graph sig e: " + e);

		this.graphSignature = new GSSignature(extendedPublicKey.getPublicKey(), A, e, v);
		this.baseCollection = (BaseCollection) proofStore.retrieve("encoded.bases");

		GSMessage msg = prover.receiveMessage();
		Map<URN, Object> messageElements = msg.getMessageElements();
		n_3 = (BigInteger) messageElements.get(URN.createZkpgsURN("verifier.n_3"));

		// TODO I prefer to have specific exceptions, not just throwing Exception.
		try {
			prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
		} catch (ProofStoreException e1) {
			gslog.log(Level.SEVERE, "Commitments not computed correctly; values not found in the ProofStore.", e1.getMessage());
		}
		commitments = prover.getCommitmentMap();
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

		//    List<PairWiseDifferenceProver> pairWiseDifferenceProvers = new ArrayList<>();
		//    PairWiseDifferenceProver pairWiseDifferenceProver;
		//
		//    List<PairWiseCommitments> commitmentPairs = getPairs((Map<URN, GSCommitment>)
		// hatV.values());
		//
		//    int index = 0;
		//    for (PairWiseCommitments commitmentPair : commitmentPairs) {
		//      pairWiseDifferenceProver =
		//          new PairWiseDifferenceProver(
		//              commitmentPair.getC_i(),
		//              commitmentPair.getC_j(),
		//              extendedPublicKey.getPublicKey().getBaseS(),
		//              extendedPublicKey.getPublicKey().getModN(),
		//              index,
		//              proofStore,
		//              keyGenParameters);
		//
		//      pairWiseDifferenceProver.precomputation();
		//
		//      pairWiseDifferenceProvers.add(pairWiseDifferenceProver);
		//      index++;
		//    }

		try {
			computeCommitmentProvers();
		} catch (ProofStoreException e) {
			gslog.log(Level.SEVERE, e.getMessage());
		}

		//    computePairWiseProvers(pairWiseDifferenceProvers);
	}

	private void storeBlindedGS() throws ProofStoreException {
		String commitmentsURN = "prover.commitments";
		proofStore.store(commitmentsURN, commitments);

		String blindedGSURN = "prover.blindedgs";
		proofStore.store(blindedGSURN, this.blindedGraphSignature);

		String APrimeURN = "prover.blindedgs.APrime";
		proofStore.store(APrimeURN, this.blindedGraphSignature.getA());

		String ePrimeURN = "prover.blindedgs.ePrime";
		proofStore.store(ePrimeURN, this.blindedGraphSignature.getEPrime());

		String vPrimeURN = "prover.blindedgs.vPrime";
		proofStore.store(vPrimeURN, this.blindedGraphSignature.getV());
	}

	@Override
	public ProofSignature createProofSignature() {
		String hateURN = "possessionprover.responses.hate";
		BigInteger hate = (BigInteger) proofStore.retrieve(hateURN);
		String hatvPrimeURN = "possessionprover.responses.hatvprime";
		BigInteger hatvPrime = (BigInteger) proofStore.retrieve(hatvPrimeURN);
		String hatm_0URN = "possessionprover.responses.hatm_0";
		BigInteger hatm_0 = (BigInteger) proofStore.retrieve(hatm_0URN);

		Map<URN, Object> proofSignatureElements = new HashMap<>();
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.c"), cChallenge);
		proofSignatureElements.put(
				URN.createZkpgsURN("proofsignature.P_3.APrime"), blindedGraphSignature.getA());
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.hate"), hate);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.hatvPrime"), hatvPrime);
		proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_3.hatm_0"), hatm_0);

		int baseIndex;
		String hatm_iPath = "possessionprover.responses.vertex.hatm_i_";
		String hatm_iURN;
		String hatr_iPath = "proving.commitmentprover.responses.hatr_i_";
		String hatr_iURN;

		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertexBase : vertexIterator) {
			baseIndex = vertexBase.getBaseIndex();
			hatm_iURN = hatm_iPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.hatm_i_" + baseIndex),
					proofStore.retrieve(hatm_iURN));
			hatr_iURN = hatr_iPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.hatr_i_" + baseIndex),
					proofStore.retrieve(hatr_iURN));
		}

		String hatm_i_jURN;
		String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";

		BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
		for (BaseRepresentation edgeBase : edgeIterator) {
			baseIndex = edgeBase.getBaseIndex();
			hatm_i_jURN = hatm_i_jPath + baseIndex;
			proofSignatureElements.put(
					URN.createZkpgsURN("proofsignature.P_3.hatm_i_j_" + baseIndex),
					proofStore.retrieve(hatm_i_jURN));
		}

		/** TODO add proof signature elements from pair wise difference prover */
		return new ProofSignature(proofSignatureElements);
	}

	@Override
	public BigInteger computeChallenge() {
		gslog.info("compute challenge ");
		challengeList = populateChallengeList();
		try {
			cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
		} catch (NoSuchAlgorithmException e) {
			gslog.log(Level.SEVERE, "Fiat-Shamir challenge could not be computed.", e);
		}
		return cChallenge;
	}

	@Override
	public void executePostChallengePhase(BigInteger c) throws IOException {
		gslog.info("compute post challlenge phase");
		try {
			responses = possessionProver.executePostChallengePhase(cChallenge);
		} catch (ProofStoreException e1) {
			gslog.log(Level.SEVERE, "Could not access the ProofStore.", e1);
			return;
		}

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
		messageElements.put(URN.createZkpgsURN("prover.C_i"), commitments);

		//    for (Entry<URN, BigInteger> entry : responses.entrySet()) {
		//      proofStore.save(entry.getKey(), entry.getValue() );
		//    }

		prover.sendMessage(new GSMessage(messageElements));
	}

	private List<String> populateChallengeList() {
		/** TODO populate context list */
		GSContext gsContext = new GSContext(extendedPublicKey);
		contextList = gsContext.computeChallengeContext();
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
			commitment = (GSCommitment) proofStore.retrieve(tildeC_iURN);
			challengeList.add(String.valueOf(commitment.getCommitmentValue()));
		}
		/** TODO add pair-wise elements for challenge */
		//    for (GroupElement witness : pairWiseWitnesses.values()) {
		//      challengeList.add(String.valueOf(witness));
		//    }
		gslog.info("n3: " + n_3);
		challengeList.add(String.valueOf(n_3));

		return challengeList;
	}

	private void computePairWiseProvers(List<PairWiseDifferenceProver> pairWiseDifferenceProvers) {
		int i = 0;
		pairWiseWitnesses = new HashMap<URN, GroupElement>();

		for (PairWiseDifferenceProver differenceProver : pairWiseDifferenceProvers) {

			try {
				differenceProver.executeCompoundPreChallengePhase();
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, "Could not access the ProofStore.", e);
				return;
			}
			tildeR_BariBarj = differenceProver.getBasetildeR_BariBarj();

			/** TODO store witness randomness tildea_BariBarj, tilbeb_BariBarj, tilder_BariBarj */
			pairWiseWitnesses.put(
					URN.createURN(
							URN.getZkpgsNameSpaceIdentifier(), "pairwiseprover.witnesses.tildeR_BariBarj" + i),
					tildeR_BariBarj);
		}
	}

	private void computeCommitmentProvers() throws ProofStoreException {
		CommitmentProver commitmentProver;
		commitmentProverList = new ArrayList<>();


		BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
		for (BaseRepresentation vertex : vertexIterator) {
			String witnessRandomnessURN = "possessionprover.witnesses.randomness.vertex.tildem_i_" + vertex.getBaseIndex();
			BigInteger tildem_i = (BigInteger) proofStore.retrieve(witnessRandomnessURN);
			String commURN = "prover.commitments.C_i_" + vertex.getBaseIndex();
			GSCommitment com = commitments.get(URN.createZkpgsURN(commURN));
			commitmentProver = new CommitmentProver(com, vertex.getBaseIndex(), extendedPublicKey.getPublicKey(), proofStore);

			GroupElement tildeCommitment = commitmentProver.executePreChallengePhase();

			commitmentProverList.add(commitmentProver);

			String tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();

			try {
				proofStore.store(tildeC_iURN, tildeCommitment);
			} catch (ProofStoreException e) {
				gslog.log(Level.SEVERE, e.getMessage());
			}
			// TODO fix indexing, semantics of the CommitmentProver.
			//      commitmentProver = new CommitmentProver(com, 0, extendedPublicKey, proofStore);
			//      GSCommitment tildeCommitment =
			//          commitmentProver.preChallengePhase(
			//              vertex, proofStore, extendedPublicKey, keyGenParameters);
			//
			//      commitmentProverList.add(commitmentProver);
			//      tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();

			//      try {
			//        proofStore.store(tildeC_iURN, tildeCommitment);
			//      } catch (Exception e) {
			//        gslog.log(Level.SEVERE, e.getMessage());
			//      }
		}
	}

	private void computeTildeZ() throws ProofStoreException {

		possessionProver = new PossessionProver(blindedGraphSignature, extendedPublicKey, proofStore);

		Map<URN, GroupElement> tildeMap = possessionProver.executeCompoundPreChallengePhase();
		tildeZ = tildeMap.get(URN.createZkpgsURN(possessionProver.getProverURN(URNType.TILDEZ)));
	}

	@Override
	public void close() throws IOException {
		prover.close();
	}
}
