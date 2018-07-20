package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.encoding.GraphEncoding;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.GSPossessionProver;
import eu.prismacloud.primitives.zkpgs.prover.GSProver;
import eu.prismacloud.primitives.zkpgs.prover.GroupSetupProver;
import eu.prismacloud.primitives.zkpgs.prover.PairWiseDifferenceProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory.ProverType;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
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
public class ProverOrchestrator implements ProofOperation {

  private GroupElement baseZ;
  private GroupElement baseS;
  private BigInteger n_3;
  private BigInteger modN;
  private GSSignature graphSignature;
  private GSSignature randomizedGraphSignature;
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
  private BigInteger tildeZ;
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
  private List<String> challengeList;
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

  public ProverOrchestrator(
      final BigInteger n_3,
      final GSProver prover,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {
    this.n_3 = n_3;
    this.prover = prover;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
  }

  public ProverOrchestrator(
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncoding graphEncoding) {

    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncoding = graphEncoding;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.proofStore = new ProofStore<Object>();
  }

  public ProverOrchestrator(BigInteger n_3) {
    this.n_3 = n_3;
  }

  public void groupSetupProver() throws NoSuchAlgorithmException {

    prover =
        new GSProver(
            extendedPublicKey.getPublicKey().getModN(),
            extendedPublicKey.getPublicKey().getBaseS(),
            this.n_3,
            proofStore,
            keyGenParameters);

    groupSetupProver = (GroupSetupProver) ProverFactory.newProver(ProverType.GroupSetupProver);
    /** TODO check if we need the extended key pair here for the group setup prover */
    groupSetupProver.preChallengePhase(
        extendedPublicKey, proofStore, keyGenParameters, graphEncodingParameters);
    groupSetupChallenge = groupSetupProver.computeChallenge();
    try {
      groupSetupProver.postChallengePhase();
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
    proofSignatureP = groupSetupProver.outputProofSignature();

    Map<URN, Object> messageElements = new HashMap<>();
    messageElements.put(URN.createZkpgsURN("proofSignature.P"), proofSignatureP);
    prover.sendMessage(new GSMessage(messageElements));
  }

  public GSSignature getRandomizedGraphSignature(final GSSignature graphSignature) {
    return graphSignature.blind();
  }

  public void computePreChallengePhase() throws Exception {
    storeBases();

    prover =
        new GSProver(
            extendedPublicKey.getPublicKey().getModN(),
            extendedPublicKey.getPublicKey().getBaseS(),
            this.n_3,
            proofStore,
            keyGenParameters);

    prover.computeCommitments(vertexRepresentations);
    commitments = prover.getCommitmentMap();

    storeBlindedGS();

    List<PairWiseDifferenceProver> pairWiseDifferenceProvers = new ArrayList<>();
    PairWiseDifferenceProver pairWiseDifferenceProver;

    List<PairWiseCommitments> commitmentPairs = getPairs((Map<URN, GSCommitment>) hatV.values());

    int index = 0;
    for (PairWiseCommitments commitmentPair : commitmentPairs) {
      pairWiseDifferenceProver =
          new PairWiseDifferenceProver(
              commitmentPair.getC_i(),
              commitmentPair.getC_j(),
              extendedPublicKey.getPublicKey().getBaseS(),
              extendedPublicKey.getPublicKey().getModN(),
              index,
              proofStore,
              keyGenParameters);

      pairWiseDifferenceProver.precomputation();

      pairWiseDifferenceProvers.add(pairWiseDifferenceProver);
      index++;
    }

    computeTildeZ();

    computeCommitmentProvers();

    computePairWiseProvers(pairWiseDifferenceProvers);
  }

  private void storeBases() throws Exception {
    String encodedBasesURN = "";

    encodedBases = graphRepresentation.getEncodedBases();

    for (BaseRepresentation baseRepresentation : encodedBases.values()) {

      if (baseRepresentation.getBaseType() == BASE.EDGE) {
        encodedBasesURN = "bases.edge.R_i_j_" + baseRepresentation.getBaseIndex();

      } else if (baseRepresentation.getBaseType() == BASE.VERTEX) {
        encodedBasesURN = "bases.vertex.R_i_" + baseRepresentation.getBaseIndex();
      }
      proofStore.store(encodedBasesURN, baseRepresentation);
    }
  }

  private void storeBlindedGS() throws Exception {
    String commitmentsURN = "prover.commitments";
    proofStore.store(commitmentsURN, commitments);

    String blindedGSURN = "prover.blindedgs";
    proofStore.store(blindedGSURN, this.randomizedGraphSignature);

    String APrimeURN = "prover.blindedgs.APrime";
    proofStore.store(APrimeURN, this.randomizedGraphSignature.getA());

    String ePrimeURN = "prover.blindedgs.ePrime";
    proofStore.store(ePrimeURN, this.randomizedGraphSignature.getE());

    String vPrimeURN = "prover.blindedgs.vPrime";
    proofStore.store(blindedGSURN, this.randomizedGraphSignature.getV());
  }

  public void computeChallenge() throws NoSuchAlgorithmException {
    this.c = CryptoUtilsFacade.computeHash(populateChallengeList(), keyGenParameters.getL_H());
  }

  public void computePostChallengePhase() {}

  private List<String> populateChallengeList() {
    /** TODO populate context list */
    GSContext gsContext =
        new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
    contextList = gsContext.computeChallengeContext();

    challengeList.addAll(contextList);
    challengeList.add(String.valueOf(randomizedGraphSignature.getA()));
    challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));
    for (GSCommitment gsCommitment : commitments.values()) {
      challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
    }

    challengeList.add(String.valueOf(tildeZ));

    for (GSCommitment gsCommitment : tildeC_i.values()) {
      challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
    }

    for (GroupElement witness : pairWiseWitnesses.values()) {
      challengeList.add(String.valueOf(witness));
    }

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
    vertices = graphRepresentation.getEncodedBases();
    CommitmentProver commitmentProver;

    /** TODO store commitments for later use */
    int i = 0;
    for (BaseRepresentation vertex : vertices.values()) {
      tildem_i =
          vertexWitnesses.get(
              URN.createURN(
                  URN.getZkpgsNameSpaceIdentifier(),
                  "possessionprover.witnesses.tildem_" + vertex.getBaseIndex()));

      commitmentProver = (CommitmentProver) ProverFactory.newProver(ProverType.CommitmentProver);
      //          new CommitmentProver(vertex, proofStore, extendedPublicKey, keyGenParameters);
      commitmentProver.createWitnessRandomness();
      commitmentProver.computeWitness();

      String tildeC_iURN = "commitmentprover.commitments.tildeC_" + vertex.getBaseIndex();
      try {
        proofStore.store(tildeC_iURN, commitmentProver.getWitness());
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
      i++;
    }
  }

  private void computeTildeZ() {
    GSPossessionProver gsPossessionProver =
        new GSPossessionProver(
            getRandomizedGraphSignature(this.graphSignature),
            extendedPublicKey,
            R_0,
            tildem_0,
            tildevPrime,
            graphRepresentation,
            proofStore,
            keyGenParameters);

    gsPossessionProver.createWitnessRandomness();
    gsPossessionProver.computeWitness();
    edgeWitnesses = gsPossessionProver.getEdgeWitnesses();
    vertexWitnesses = gsPossessionProver.getVertexWitnesses();
    tildeZ = gsPossessionProver.getTildeZ();
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

  public void sendPreChallenge(ProofOperation proofCommand) {
    proofCommand.execute();
  }

  public void sendPostChallenge() {}

  public void execute(GSSignature randomizedGraphSignature) {}

  @Override
  public void execute() {}
}
