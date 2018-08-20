package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Commitment prover. */
public class CommitmentProver implements IProver {
	
	public static final String URNID = "commitmentprover";

  public static final String RANDOMNESS_TILDEM_I =
      "issuing.commitmentprover.witnesses.randomness.vertex.tildem_i_";

  public static final String RANDOMNESS_TILDEM_I_J =
      "issuing.commitmentprover.witnesses.randomness.edge.tildem_i_j_";

  public static final String RANDOMNESS_TILDEM_0 =
      "issuing.commitmentprover.witnesses.randomness.vertex.tildem_0";

  public static final String RANDOMNESS_VERTEX_TILDER =
      "commitmentprover.witnesses.randomness.vertex.tilder_";

  public static final String POSSESSIONPROVER_WITNESSES_RANDOMNESS_TILDEM =
      "possessionprover.witnesses.randomness.tildem_i";

  public static final String POSSESSIONPROVER_WITNESSES_VERTEX_RANDOMNESS_TILDEM =
      "possessionprover.witnesses.randomness.vertex.tildem_i_";
  private static final String RANDOMNESS_TILDEVPRIME =
      "possessionprover.witnesses.randomness.tildevPrime";

  private BaseCollection baseCollection;
  private ProofStore<Object> proofStore;
  private ExtendedPublicKey extendedPublicKey;
  private KeyGenParameters keyGenParameters;
  private BigInteger modN;
  private GroupElement baseS;
  private BigInteger tilder_i;
  private GSCommitment witness;
  private final Logger gslog = GSLoggerConfiguration.getGSlog();
  private BigInteger cChallenge;
  private STAGE proofStage;
  private BigInteger tildevPrime;
  private BigInteger tildem_0;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private final Map<URN, BigInteger> responses = new LinkedHashMap<URN, BigInteger>();
  private BaseRepresentation baseRepresentationR_0;
  private BaseIterator vertexIterator;
  private BaseIterator edgeIterator;
  private BaseIterator baseR0Iterator;
  private BaseRepresentation base;

  @Override
  public void executePrecomputation() {
	  // NO PRE-COMPUTATION IS NEEDED: NO-OP.
  }
  
  public GroupElement executePreChallengePhase() throws ProofStoreException {
	  throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
  
  public Map<URN, BigInteger> executePostChallengePhase(BigInteger cChallenge) throws ProofStoreException {
	  throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
  
  /**
   * Pre challenge phase for commitment prover in the proving stage.
   *
   * @param base the base
   * @param proofStore the proof store
   * @param extendedPublicKey the extended public key
   * @param keyGenParameters the key gen parameters
   * @return the gs commitment
   */
  public GSCommitment preChallengePhase(
      final BaseRepresentation base,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters) {

    Assert.notNull(base, "base must not be null");
    Assert.notNull(proofStore, "proof store must not be null");
    Assert.notNull(extendedPublicKey, "extended public key must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");
    this.base = base;
    this.proofStore = proofStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.proofStage = STAGE.PROVING;

    createWitnessRandomness();
    computeWitness();
    return witness;
  }

  public enum STAGE {
    ISSUING,
    PROVING
  }

  /**
   * Pre challenge phase for commitment prover in the issuing stage.
   *
   * @param baseCollection the base collection
   * @param proofStore the proof store
   * @param extendedPublicKey the extended public key
   * @param keyGenParameters the key generation parameters
   * @return the gs outputs a commitment
   */
  public GSCommitment preChallengePhase(
      final BaseCollection baseCollection,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters) {

    Assert.notNull(baseCollection, "baseCollection must not be null");
    Assert.notNull(proofStore, "proof store must not be null");
    Assert.notNull(extendedPublicKey, "extended public key must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");

    this.baseCollection = baseCollection;
    this.proofStore = proofStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.proofStage = STAGE.ISSUING;

    if (baseCollection.size() > 1) {
      this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
      this.edgeIterator = baseCollection.createIterator(BASE.EDGE);
    }
    this.baseR0Iterator = baseCollection.createIterator(BASE.BASE0);

    createWitnessRandomness();
    computeWitness();
    return witness;
  }

  @Override
  public void createWitnessRandomness() {
    if (proofStage == STAGE.ISSUING) {

      try {
        witnessRandomnessIssuing();
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }

    } else {
      witnessRandomnessProving();
    }
  }

  private void witnessRandomnessIssuing() throws Exception {
    URN urnVertex;
    URN urnEdge;
    int tildevPrimeBitLength =
        keyGenParameters.getL_n()
            + (2 * keyGenParameters.getL_statzk())
            + keyGenParameters.getL_H();

    tildevPrime = CryptoUtilsFacade.computeRandomNumberMinusPlus(tildevPrimeBitLength);
    proofStore.store(RANDOMNESS_TILDEVPRIME, tildevPrime);

    int mBitLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

    tildem_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
    proofStore.store(RANDOMNESS_TILDEM_0, tildem_0);

    Map<URN, BigInteger> vertexWitnessRandomness = new HashMap<URN, BigInteger>();
    if (baseCollection.size() > 1) {
      for (BaseRepresentation baseRepresentation : vertexIterator) {
        urnVertex = URN.createZkpgsURN(RANDOMNESS_TILDEM_I + baseRepresentation.getBaseIndex());
        tildem_i = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
        vertexWitnessRandomness.put(urnVertex, tildem_i);
        proofStore.store(RANDOMNESS_TILDEM_I + baseRepresentation.getBaseIndex(), tildem_i);
      }

      for (BaseRepresentation baseRepresentation : edgeIterator) {
        urnEdge = URN.createZkpgsURN(RANDOMNESS_TILDEM_I_J + baseRepresentation.getBaseIndex());
        tildem_i_j = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
        vertexWitnessRandomness.put(urnEdge, tildem_i_j);
        proofStore.store(RANDOMNESS_TILDEM_I_J + baseRepresentation.getBaseIndex(), tildem_i_j);
      }
    }
  }

  private void witnessRandomnessProving() {
    int tilder_iLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

    tilder_i = CryptoUtilsFacade.computeRandomNumber(tilder_iLength);

    String tilder_iURN = RANDOMNESS_VERTEX_TILDER + base.getBaseIndex();

    try {
      proofStore.store(tilder_iURN, tilder_i);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  @Override
  public GroupElement computeWitness() {
    Map<URN, GroupElement> baseMap = new HashMap<>();
    Map<URN, BigInteger> exponentsMap = new HashMap<>();

    GroupElement R_0 = extendedPublicKey.getPublicKey().getBaseR_0();

    if (proofStage == STAGE.ISSUING) {
      baseMap.put(URN.createZkpgsURN("commitment.R_0"), R_0);
      exponentsMap.put(URN.createZkpgsURN("commitment.tildem_0"), tildem_0);

      //      /** TODO refactor with iterator */
      //      if (baseCollection.size() > 1) {
      //        for (BaseRepresentation baseRepresentation : baseCollection.) {
      //          baseMap.put(
      //              URN.createZkpgsURN("commitment.R_i_" + baseRepresentation.getBaseIndex()),
      //              baseRepresentation.getBase());
      //          exponentsMap.put(
      //              URN.createZkpgsURN("commitment.m_i_" + baseRepresentation.getBaseIndex()),
      //              baseRepresentation.getExponent());
      //        }
      //      }

      baseMap.put(URN.createZkpgsURN("commitment.S"), baseS);
      exponentsMap.put(URN.createZkpgsURN("commitments.tildevPrime"), tildevPrime);

      GroupElement sMulti = baseS.modPow(tildevPrime);
      GroupElement tildeU = sMulti.multiply(R_0.modPow(tildem_0));

      witness = new GSCommitment(tildeU);

      gslog.info("witness U: " + witness.getCommitmentValue());

    } else {

      /** TODO retrieve witness randomness of committed messages from the common store */
      //      String tildem_iURN = POSSESSIONPROVER_WITNESSES_RANDOMNESS_TILDEM; // +
      // base.getBaseIndex();
      //      Map<URN, BigInteger> witnesses = (Map<URN, BigInteger>)
      // proofStore.retrieve(tildem_iURN);

      String tildem_i_iURN =
          POSSESSIONPROVER_WITNESSES_VERTEX_RANDOMNESS_TILDEM + base.getBaseIndex();
      tildem_i = (BigInteger) proofStore.retrieve(tildem_i_iURN);
      GroupElement baseR = extendedPublicKey.getPublicKey().getBaseR();
      GroupElement tildeC_i = baseR.modPow(tildem_i).multiply(baseS.modPow(tilder_i));

      //      baseMap.put(URN.createZkpgsURN("commitment.base.R_" + vertex.getBaseIndex()), R_i);
      //      exponentsMap.put(
      //          URN.createZkpgsURN("commitment.exponent.m_" + vertex.getBaseIndex()), tildem_i);

      witness = new GSCommitment(tildeC_i);
    }

    return witness.getCommitmentValue();
  }

  @Override
  public BigInteger computeChallenge() {

    return BigInteger.ZERO;
  }

  @Override
  public void computeResponses() {}

  /**
   * Post challenge phase computes responses.
   *
   * @param cChallenge the common challenge c
   * @return the map outputs responses
   */
  public Map<URN, BigInteger> postChallengePhase(BigInteger cChallenge) {
    this.cChallenge = cChallenge;

    if (this.proofStage == STAGE.ISSUING) {
      try {
        computeResponsesIssuing();
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }

    } else if (this.proofStage == STAGE.PROVING) {
      try {
        return computeResponsesProving();
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }

    return responses;
  }

  private void computeResponsesIssuing() throws Exception {
    BigInteger m_0 = null;
    BaseRepresentation baseRepresentation;
    BigInteger vPrime = (BigInteger) proofStore.retrieve("issuing.recipient.vPrime");

    if (baseR0Iterator.hasNext()) {
      m_0 = baseR0Iterator.next().getExponent();
    }

    BigInteger hatvPrime = tildevPrime.add(cChallenge.multiply(vPrime));
    BigInteger hatm_0 = tildem_0.add(cChallenge.multiply(m_0));
    String hatvPrimeURN = "issuing.commitmentprover.responses.hatvPrime";
    String hatm_0URN = "issuing.commitmentprover.responses.hatm_0";
    String cChallengeURN = "issuing.commitmentprover.commitment.C";

    responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);
    responses.put(URN.createZkpgsURN(hatm_0URN), hatm_0);
    proofStore.store(hatvPrimeURN, hatvPrime);
    proofStore.store(hatm_0URN, hatm_0);
    proofStore.store(cChallengeURN, cChallenge);

    if (baseCollection.size() > 0) {

      for (BaseRepresentation base : vertexIterator) {
        tildem_i = (BigInteger) proofStore.retrieve(RANDOMNESS_TILDEM_I + base.getBaseIndex());
        BigInteger hatm_i = tildem_i.add(cChallenge.multiply(base.getExponent()));
        String hatm_iURN = "issuing.commitmentprover.responses.hatm_i_" + base.getBaseIndex();
        responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);

        proofStore.store(hatm_iURN, base);
      }

      for (BaseRepresentation base : edgeIterator) {
        tildem_i_j = (BigInteger) proofStore.retrieve(RANDOMNESS_TILDEM_I_J + base.getBaseIndex());
        BigInteger hatm_i_j = tildem_i_j.add(cChallenge.multiply(base.getExponent()));
        String hatm_i_jURN = "issuing.commitmentprover.responses.hatm_i_j_" + base.getBaseIndex();
        responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);
        proofStore.store(
            "issuing.commitmentprover.responses.hatm_i_j_" + base.getBaseIndex(), base);
      }
    }
  }

  /**
   * Compute responses proving.
   *
   * @throws Exception the exception
   */
  public Map<URN, BigInteger> computeResponsesProving() throws Exception {
    String tilder_iURN =
        "commitmentprover.witnesses.randomness.vertex.tilder_" + base.getBaseIndex();
    tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);

    String C_iURN = "prover.commitments.C_" + base.getBaseIndex();
    Map<URN, GSCommitment> commitmentMap =
        (Map<URN, GSCommitment>) proofStore.retrieve("prover.commitments");
    GSCommitment C_i = commitmentMap.get(URN.createZkpgsURN(C_iURN));
    BigInteger r_i = C_i.getRandomness();

    BigInteger hatr_i = tilder_i.add(this.cChallenge.multiply(r_i));

    String hatr_iURN = "proving.commitmentprover.responses.hatr_i_" + base.getBaseIndex();

    responses.put(URN.createZkpgsURN(hatr_iURN), hatr_i);
    gslog.info("store hatr_i " + hatr_i);
    proofStore.store(hatr_iURN, hatr_i);
    return responses;
  }

  public boolean isSetupComplete() {
	  return false;
  }
  
  @Override
  public boolean verify() {
    return false;
  }
  
  public List<URN> getGovernedURNs() {
	  throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
