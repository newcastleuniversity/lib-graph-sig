package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.GraphSignature;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.GSPossessionProver;
import eu.prismacloud.primitives.zkpgs.prover.GSProver;
import eu.prismacloud.primitives.zkpgs.prover.PairWiseDifferenceProver;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** Orchestrate provers */
public class ProverOrchestrator implements ProofOperation {

  private final BigInteger n_3;
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
  private Map<URN, BigInteger> pairWiseWitnesses;
  private List<BigInteger> challengeList;
  private BigInteger tildeR_BariBarj;
  private BigInteger c;
  private ProofStore<Object> proverStore = new ProofStore<Object>();
  private URN r_BariBarjURN;
  private BigInteger a_BariBarj;
  private BigInteger b_BariBarj;
  private URN a_BariBarjURN;
  private URN b_BariBarjURN;
  private Map<URN, BaseRepresentation> encodedBases;
  private Map<URN, BaseRepresentation> encodedVertexBases;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public ProverOrchestrator(BigInteger n_3, GSProver prover) {
    this.n_3 = n_3;
    this.prover = prover;
  }

  public ProverOrchestrator(BigInteger n_3) {
    this.n_3 = n_3;
  }

  public void ProverOrchestrator(final GSSignature graphSignature) {
    this.graphSignature = graphSignature;
    this.randomizedGraphSignature = getRandomizedGraphSignature(this.graphSignature);
  }

  public GSSignature getRandomizedGraphSignature(final GSSignature graphSignature) {
    return graphSignature.blind(
        graphSignature.getA(), graphSignature.getE(), graphSignature.getV());
  }

  public void computePreChallengePhase() throws Exception {
    storeBases();

    prover =
        new GSProver(
            extendedPublicKey.getPublicKey().getModN(),
            extendedPublicKey.getPublicKey().getBaseS(),
            this.n_3,
            proverStore,
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
              extendedPublicKey.getPublicKey().getBaseS().getValue(),
              extendedPublicKey.getPublicKey().getModN(),
              index,
              proverStore,
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
    encodedBases = GraphRepresentation.getEncodedBases();

    for (BaseRepresentation baseRepresentation : encodedBases.values()) {

      if (baseRepresentation.getBaseType() == BASE.EDGE) {
        encodedBasesURN = "bases.edge.R_i_j_" + baseRepresentation.getBaseIndex();

      } else if (baseRepresentation.getBaseType() == BASE.VERTEX) {
        encodedBasesURN = "bases.vertex.R_i_" + baseRepresentation.getBaseIndex();
      }
      proverStore.store(encodedBasesURN, baseRepresentation);
    }
  }

  private void storeBlindedGS() throws Exception {
    String commitmentsURN = "prover.commitments";
    proverStore.store(commitmentsURN, commitments);

    String blindedGSURN = "prover.blindedgs";
    proverStore.store(blindedGSURN, this.randomizedGraphSignature);

    String APrimeURN = "prover.blindedgs.APrime";
    proverStore.store(APrimeURN, this.randomizedGraphSignature.getA());

    String ePrimeURN = "prover.blindedgs.ePrime";
    proverStore.store(ePrimeURN, this.randomizedGraphSignature.getE());

    String vPrimeURN = "prover.blindedgs.vPrime";
    proverStore.store(blindedGSURN, this.randomizedGraphSignature.getV());
  }

  public void computeChallenge() {
    this.c = CryptoUtilsFacade.computeHash(populateChallengeList(), keyGenParameters.getL_H());
    //            prover.computeChallenge(populateChallengeList());
  }

  public void computePostChallengePhase() {}

  private List<BigInteger> populateChallengeList() {
    /** TODO populate context list */
    challengeList.add(randomizedGraphSignature.getA());
    challengeList.add(extendedPublicKey.getPublicKey().getBaseZ().getValue());
    for (GSCommitment gsCommitment : commitments.values()) {
      challengeList.add(gsCommitment.getCommitmentValue());
    }

    challengeList.add(tildeZ);

    for (GSCommitment gsCommitment : tildeC_i.values()) {
      challengeList.add(gsCommitment.getCommitmentValue());
    }

    for (BigInteger witness : pairWiseWitnesses.values()) {
      challengeList.add(witness);
    }

    challengeList.add(n_3);

    return challengeList;
  }

  private void computePairWiseProvers(List<PairWiseDifferenceProver> pairWiseDifferenceProvers) {
    int i = 0;

    for (PairWiseDifferenceProver differenceProver : pairWiseDifferenceProvers) {

      differenceProver.createWitnessRandomness();
      differenceProver.computeWitness();
      tildeR_BariBarj = differenceProver.getTildeR_BariBarj();

      /** TODO store witness randomness tildea_BariBarj, tilbeb_BariBarj, tilder_BariBarj */
      pairWiseWitnesses.put(
          URN.createURN(
              URN.getZkpgsNameSpaceIdentifier(), "pairwiseprover.witnesses.tildeR_BariBarj" + i),
          tildeR_BariBarj);
    }
  }

  private void computeCommitmentProvers() {
    vertices = GraphRepresentation.getEncodedBases();
    CommitmentProver commitmentProver;

    /** TODO store commitments for later use */
    int i = 0;
    for (BaseRepresentation vertex : vertices.values()) {
      tildem_i =
          vertexWitnesses.get(
              URN.createURN(
                  URN.getZkpgsNameSpaceIdentifier(),
                  "possessionprover.witnesses.tildem_" + vertex.getBaseIndex()));

      commitmentProver =
          new CommitmentProver(vertex, proverStore, extendedPublicKey, keyGenParameters);
      commitmentProver.createWitnessRandomness();
      commitmentProver.computeWitness();

      String tildeC_iURN = "commitmentprover.commitments.tildeC_" + vertex.getBaseIndex();
      try {
        proverStore.store(tildeC_iURN, commitmentProver.getWitness());
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
            proverStore,
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

  public void execute(GraphSignature randomizedGraphSignature) {}

  @Override
  public void execute() {}
}
