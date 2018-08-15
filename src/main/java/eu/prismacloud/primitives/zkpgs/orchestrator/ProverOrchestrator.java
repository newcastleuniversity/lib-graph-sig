package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.encoding.GraphEncoding;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.GSProver;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.PairWiseDifferenceProver;
import eu.prismacloud.primitives.zkpgs.prover.PossessionProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory.ProverType;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.GSVerifier;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Orchestrate provers */
public class ProverOrchestrator { // implements ProofOperation {

  private BaseCollection baseCollection;
  private GroupElement baseZ;
  private GroupElement baseS;
  private BigInteger n_3;
  private BigInteger modN;
  private GSSignature graphSignature;
  private GSSignature blindedGraphSignature;
  private ProofOperation proofCommand;
  private GSProver prover;
  private Map<URN, BaseRepresentation> vertexRepresentations;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger R_0;
  private BigInteger tildem_0;
  private BigInteger tildevPrime;
  private GraphRepresentation graphRepresentation;
  private KeyGenParameters keyGenParameters;
  private GraphEncoding graphEncoding;
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
  private BigInteger r_BariBarj;
  private Map<URN, BigInteger> edgeWitnesses;
  private Map<URN, BigInteger> vertexWitnesses;
  private BigInteger tildem_i;
  private BigInteger tilder_i;
  private Map<URN, GroupElement> pairWiseWitnesses;
  private List<String> challengeList = new ArrayList<String>();
  private GroupElement tildeR_BariBarj;
  private BigInteger c;
  private ProofStore<Object> proofStore;
  private URN r_BariBarjURN;
  private BigInteger a_BariBarj;
  private BigInteger b_BariBarj;
  private URN a_BariBarjURN;
  private URN b_BariBarjURN;
  private Map<URN, BaseRepresentation> encodedBases;
  private Map<URN, BaseRepresentation> encodedVertexBases;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private List<String> contextList;
  private GroupSetupProver groupSetupProver;
  private BigInteger groupSetupChallenge;
  private ProofSignature proofSignatureP;
  private GSVerifier verifier;
  private BigInteger cChallenge;
  private BaseIterator vertexIterator;
  private PossessionProver possessionProver;
  private List<CommitmentProver> commitmentProverList;
  private BaseIterator edgeIterator;

  public ProverOrchestrator(
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
//    this.baseCollection = extendedPublicKey.getBaseCollection();
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.proofStore = proofStore;
    this.prover = new GSProver(extendedPublicKey, keyGenParameters);
//    this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
  }

  public void init() throws Exception {
    GroupElement A = (GroupElement) proofStore.retrieve("graphsignature.A");
    BigInteger e = (BigInteger) proofStore.retrieve("graphsignature.e");
    BigInteger v = (BigInteger) proofStore.retrieve("graphsignature.v");
    gslog.info("graph sig e: " + e);

    this.graphSignature = new GSSignature(extendedPublicKey.getPublicKey(), A, e, v);
    this.baseCollection = (BaseCollection) proofStore.retrieve("encoded.bases");
    this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    this.edgeIterator = baseCollection.createIterator(BASE.EDGE);
    
    GSMessage msg = prover.receiveMessage();
    Map<URN, Object> messageElements = msg.getMessageElements();
    n_3 = (BigInteger) messageElements.get(URN.createZkpgsURN("verifier.n_3"));

    prover.computeCommitments(baseCollection.createIterator(BASE.VERTEX));
    commitments = prover.getCommitmentMap();
  }

  public void computePreChallengePhase() throws Exception {
    this.blindedGraphSignature = graphSignature.blind();
    storeBlindedGS();
    computeTildeZ();

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

//    computeCommitmentProvers();

    //    computePairWiseProvers(pairWiseDifferenceProvers);
  }

  private void storeBlindedGS() throws Exception {
    String commitmentsURN = "prover.commitments";
    proofStore.store(commitmentsURN, commitments);

    String blindedGSURN = "prover.blindedgs";
    proofStore.store(blindedGSURN, this.blindedGraphSignature);

    String APrimeURN = "prover.blindedgs.APrime";
    proofStore.store(APrimeURN, this.blindedGraphSignature.getA());

    String ePrimeURN = "prover.blindedgs.ePrime";
    proofStore.store(ePrimeURN, this.blindedGraphSignature.getE());

    String vPrimeURN = "prover.blindedgs.vPrime";
    proofStore.store(vPrimeURN, this.blindedGraphSignature.getV());
  }

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
    for (BaseRepresentation vertexBase : vertexIterator) {
      baseIndex = vertexBase.getBaseIndex();
      hatm_iURN = hatm_iPath + baseIndex;
      proofSignatureElements.put(
          URN.createZkpgsURN("proofsignature.P_3.hatm_i_" + baseIndex),
          proofStore.retrieve(hatm_iURN));
    }

    String hatm_i_jURN;
    String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";
    String hatr_iPath = "proving.commitmentprover.responses.hatr_i_";
    String hatr_iURN;
    for (BaseRepresentation edgeBase : edgeIterator) {
      baseIndex = edgeBase.getBaseIndex();
      hatm_i_jURN = hatm_i_jPath + baseIndex;
      proofSignatureElements.put(
          URN.createZkpgsURN("proofsignature.P_3.hatm_i_j_" + baseIndex),
          proofStore.retrieve(hatm_i_jURN));

      hatr_iURN = hatr_iPath + baseIndex;
      proofSignatureElements.put(
          URN.createZkpgsURN("proofsignature.P_3.hatr_i_" + baseIndex),
          proofStore.retrieve(hatr_iURN));
    }

    /** TODO add proof signature elements from pair wise difference prover */
    return new ProofSignature(proofSignatureElements);
  }

  public void computeChallenge() throws NoSuchAlgorithmException {
    gslog.info("compute challenge ");
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  public void computePostChallengePhase() {
    gslog.info("compute post challlenge phase");
    possessionProver.postChallengePhase(cChallenge);

//    for (CommitmentProver commitmentProver : commitmentProverList) {
//      commitmentProver.postChallengePhase(cChallenge);
//    }

    ProofSignature P_3 = createProofSignature();

    Map<URN, Object> messageElements = new HashMap<>();
    messageElements.put(URN.createZkpgsURN("prover.P_3"), P_3);

    // add public values
    messageElements.put(URN.createZkpgsURN("prover.APrime"), blindedGraphSignature.getA());
    messageElements.put(URN.createZkpgsURN("prover.C_i"), commitments);

    prover.sendMessage(new GSMessage(messageElements));
  }

  private List<String> populateChallengeList() {
    /** TODO populate context list */
    GSContext gsContext =
        new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
    //    contextList = gsContext.computeChallengeContext();
    //
    //    challengeList.addAll(contextList);
        challengeList.add(String.valueOf(blindedGraphSignature.getA()));
   // challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));
    //    for (GSCommitment gsCommitment : commitments.values()) {
    //      challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
    //    }

    challengeList.add(String.valueOf(tildeZ));

    //    String tildeC_iURN;
    //    for (BaseRepresentation vertex : vertexIterator) {
    //      tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();
    //      commitment = (GSCommitment) proofStore.retrieve(tildeC_iURN);
    //      challengeList.add(String.valueOf(commitment.getCommitmentValue()));
    //    }
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

    for (PairWiseDifferenceProver differenceProver : pairWiseDifferenceProvers) {

      differenceProver.createWitnessRandomness();
      differenceProver.computeWitness();
      tildeR_BariBarj = differenceProver.getBasetildeR_BariBarj();

      /** TODO store witness randomness tildea_BariBarj, tilbeb_BariBarj, tilder_BariBarj */
      pairWiseWitnesses.put(
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(), "pairwiseprover.witnesses.tildeR_BariBarj" + i),
          tildeR_BariBarj);
    }
  }

  private void computeCommitmentProvers() {
    CommitmentProver commitmentProver;
    commitmentProverList = new ArrayList<>();

    String witnessRandomnessURN = "";
    String tildeC_iURN = "";
    for (BaseRepresentation vertex : vertexIterator) {
      witnessRandomnessURN =
          "possessionprover.witnesses.randomness.vertex.tildem_i_" + vertex.getBaseIndex();
      tildem_i = (BigInteger) proofStore.retrieve(witnessRandomnessURN);

      commitmentProver = (CommitmentProver) ProverFactory.newProver(ProverType.CommitmentProver);
      GSCommitment tildeCommitment =
          commitmentProver.preChallengePhase(
              vertex, proofStore, extendedPublicKey, keyGenParameters);

      commitmentProverList.add(commitmentProver);
      tildeC_iURN = "commitmentprover.commitments.tildeC_i_" + vertex.getBaseIndex();

      try {
        proofStore.store(tildeC_iURN, tildeCommitment);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }
  }

  private void computeTildeZ() {

    possessionProver = (PossessionProver) ProverFactory.newProver(ProverType.PossessionProver);

    tildeZ =
        possessionProver.preChallengePhase(
            blindedGraphSignature, extendedPublicKey, baseCollection, proofStore, keyGenParameters);
  }

  public List<PairWiseCommitments> getPairs(Map<URN, GSCommitment> commitments) {
    GSCommitment C_i;
    GSCommitment C_j;
    BigInteger hatV_i;
    BigInteger hatV_j;
    BigInteger r_bari;
    BigInteger r_barj;
    int n = vertices.size();
    int i = 0;
    int j = i + 1;

    /** TODO improve algorithm for generating distinct pairs */
    while (true) {
      C_i = commitments.get(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "commitments.C_" + i));
      C_j = commitments.get(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "commitments.C_" + j));

      pairWiseVertices.add(new PairWiseCommitments(C_i, C_j));

      j++;

      if (j >= n) {
        i++;
        j = i + 1;
      }

      if (i >= (n - 1)) {
        break;
      }
    }

    return pairWiseVertices;
  }
}
