package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Commitment prover. */
public class CommitmentProver implements IProver {

  private GSCommitment u;
  private Map<URN, BaseRepresentation> baseRepresentationMap;
  private ProofStore<Object> proofStore;
  private GSCommitment commmitmentU;
  private BigInteger vPrime;
  private GroupElement R_0;
  private BigInteger m_0;
  private BigInteger n_1;
  private Map<URN, BaseRepresentation> vertices;
  private BaseRepresentation vertex;
  private ExtendedPublicKey extendedPublicKey;
  private KeyGenParameters keyGenParameters;
  private final Map<URN, BigInteger> witnesses = new HashMap<>();
  private BigInteger modN;
  private GroupElement baseS;
  private BigInteger tildeC_i;
  private BigInteger tilder_i;
  private GroupElement R_i;
  private GSCommitment witness;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private String tilder_iURN;
  private BigInteger cChallenge;
  private BigInteger hatr_i;
  private STAGE proofStage;
  private BigInteger tildevPrime;
  private BigInteger tildem_0;
  private BigInteger tildem_i;
  private BigInteger tildem_i_j;
  private BigInteger tildeU;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private BigInteger hatm_i;
  private BigInteger hatm_i_j;
  private final Map<URN, BigInteger> responses = new LinkedHashMap<URN, BigInteger>();

  public enum STAGE {
    ISSUING,
    PROVING
  };

  //  /**
  //   * Instantiates a new Commitment prover.
  //   *
  //   * @param baseRepresentationMap the base representation map
  //   * @param proofStore the proof store
  //   * @param extendedPublicKey the extended public key
  //   * @param keyGenParameters the key gen parameters
  //   */
  //  public CommitmentProver(
  //      final Map<URN, BaseRepresentation> baseRepresentationMap,
  //      final ProofStore<Object> proofStore,
  //      final ExtendedPublicKey extendedPublicKey,
  //      final KeyGenParameters keyGenParameters) {
  //
  //    Assert.notNull(baseRepresentationMap, "baseRepresentationMap must not be null");
  //    Assert.notNull(proofStore, "store must not be null");
  //    Assert.notNull(extendedPublicKey, "extended public key must not be null");
  //    Assert.notNull(keyGenParameters, "keygen parameters must not be null");
  //
  //    this.baseRepresentationMap = baseRepresentationMap;
  //    this.proofStore = proofStore;
  //    this.extendedPublicKey = extendedPublicKey;
  //    this.keyGenParameters = keyGenParameters;
  //    this.modN = extendedPublicKey.getPublicKey().getModN();
  //    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
  //  }

  public GSCommitment preChallengePhase(
      final Map<URN, BaseRepresentation> baseRepresentationMap,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final STAGE proofStage) {

    Assert.notNull(baseRepresentationMap, "baseRepresentationMap must not be null");
    Assert.notNull(proofStore, "store must not be null");
    Assert.notNull(extendedPublicKey, "extended public key must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");

    this.baseRepresentationMap = baseRepresentationMap;
    this.proofStore = proofStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.proofStage = proofStage;

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
        e.printStackTrace();
      }

    } else {
      witnessRandomnessProving();
    }
  }

  private void witnessRandomnessIssuing() throws Exception {

    URN urnVertex;
    URN urnEdge;
    int tildevPrimeBitLength =
        keyGenParameters.getL_n() + 2 * keyGenParameters.getL_statzk() + keyGenParameters.getL_H();

    tildevPrime = CryptoUtilsFacade.computeRandomNumberMinusPlus(tildevPrimeBitLength);

    int mBitLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

    tildem_0 = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
    proofStore.store("issuing.commitmentprover.witnesses.randomness.vertex.tildem_0", tildem_i);

    Map<URN, BigInteger> vertexWitnessRandomness = new HashMap<>();

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {
        urnVertex =
            URN.createZkpgsURN(
                "issuing.commitmentprover.witnesses.randomness.vertex.tildem_i_"
                    + baseRepresentation.getBaseIndex());
        tildem_i = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
        vertexWitnessRandomness.put(urnVertex, tildem_i);
        proofStore.store(
            "issuing.commitmentprover.witnesses.randomness.vertex.tildem_i_"
                + baseRepresentation.getBaseIndex(),
            tildem_i);
      } else if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        urnEdge =
            URN.createZkpgsURN(
                "issuing.commitmentprover.witnesses.randomness.edge.tildem_i_j_"
                    + baseRepresentation.getBaseIndex());
        tildem_i_j = CryptoUtilsFacade.computeRandomNumberMinusPlus(mBitLength);
        vertexWitnessRandomness.put(urnEdge, tildem_i_j);
        proofStore.store(
            "issuing.commitmentprover.witnesses.randomness.vertex.tildem_i_j_"
                + baseRepresentation.getBaseIndex(),
            tildem_i_j);
      }
    }
  }

  private void witnessRandomnessProving() {
    int tilder_iLength =
        keyGenParameters.getL_n()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;

    tilder_i = CryptoUtilsFacade.computeRandomNumber(tilder_iLength);

    /** TODO store witness randomness tilder_i */
    tilder_iURN = "commitmentprover.witnesses.randomness.vertex.tilder_" + vertex.getBaseIndex();

    try {
      proofStore.store(tilder_iURN, tilder_i);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  @Override
  public void computeWitness() {
    BigInteger R_0tildem_0;
    Map<URN, GroupElement> baseMap = new HashMap<>();
    Map<URN, BigInteger> exponentsMap = new HashMap<>();

    if (proofStage == STAGE.ISSUING) {

      R_0tildem_0 = R_0.modPow(tildem_0, modN).getValue();
      baseMap.put(URN.createZkpgsURN("commitment.R_0"), R_0);
      exponentsMap.put(URN.createZkpgsURN("commitment.m_0"), tildem_0);
      for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
        baseMap.put(
            URN.createZkpgsURN("commitment.R_i_" + baseRepresentation.getBaseIndex()),
            baseRepresentation.getBase());
        exponentsMap.put(
            URN.createZkpgsURN("commitment.m_i_" + baseRepresentation.getBaseIndex()),
            baseRepresentation.getExponent());
      }
      baseMap.put(URN.createZkpgsURN("commitment.S"), baseS);
      exponentsMap.put(URN.createZkpgsURN("commitments.tildevPrime"), tildevPrime);

      tildeU = CryptoUtilsFacade.computeMultiBaseEx(baseMap, exponentsMap, modN);
      witness = new GSCommitment(baseMap, exponentsMap, tildevPrime, baseS, modN);

    } else {

      /** TODO retrieve witness randomness of committed messages from the common store */
      String tildem_i_iURN =
          "possessionprover.witnesses.randomness.tildem_" + vertex.getBaseIndex();
      BigInteger tildem_i = (BigInteger) proofStore.retrieve(tildem_i_iURN);

      R_i = vertex.getBase();
      tildeC_i = R_i.modPow(tildem_i, modN).multiply(baseS.modPow(tilder_i, modN)).getValue();

      baseMap.put(URN.createZkpgsURN("commitment.base.R_" + vertex.getBaseIndex()), R_i);
      exponentsMap.put(
          URN.createZkpgsURN("commitment.exponent.m_" + vertex.getBaseIndex()), tildem_i);

      witness = new GSCommitment(baseMap, exponentsMap, tilder_i, baseS, modN);
    }
  }

  /**
   * Gets witnesses.
   *
   * @return the witnesses
   */
  public Map<URN, BigInteger> getWitnesses() {
    return this.witnesses;
  }

  @Override
  public BigInteger computeChallenge() {

    return BigInteger.ZERO;
  }

  @Override
  public void computeResponses() {}

  public Map<URN, BigInteger> postChallengePhase(BigInteger cChallenge) {
    this.cChallenge = cChallenge;

    if (this.proofStage == STAGE.ISSUING) {
      try {
        computeResponsesIssuing();
      } catch (Exception e) {
        e.printStackTrace();
      }

    } else if (this.proofStage == STAGE.PROVING) {
      try {
        computeResponsesProving();
      } catch (Exception e) {
        e.printStackTrace();
      }
    }

    return responses;
  }

  private void computeResponsesIssuing() throws Exception {
    BaseRepresentation baseRepresentation;

    hatvPrime = tildevPrime.add(cChallenge.multiply(vPrime));
    hatm_0 = tildem_0.add(cChallenge.multiply(m_0));
    String hatvPrimeURN = "issuing.commitmentprover.responses.hatvPrime";
    String hatm_0URN = "issuing.commitmentprover.responses.hatm_0";

    responses.put(URN.createZkpgsURN(hatvPrimeURN), hatvPrime);
    responses.put(URN.createZkpgsURN(hatm_0URN), hatm_0);
    proofStore.store(hatvPrimeURN, hatvPrime);
    proofStore.store(hatm_0URN, hatm_0);

    for (BaseRepresentation base : baseRepresentationMap.values()) {

      if (base.getBaseType() == BASE.VERTEX) {
        hatm_i = tildem_i.add(cChallenge.multiply(base.getExponent()));
        String hatm_iURN = "issuing.commitmentprover.responses.hatm_i_" + base.getBaseIndex();
        responses.put(URN.createZkpgsURN(hatm_iURN), hatm_i);

        proofStore.store(hatm_iURN, base);

      } else if (base.getBaseType() == BASE.EDGE) {
        hatm_i_j = tildem_i_j.add(cChallenge.multiply(base.getExponent()));
        String hatm_i_jURN = "issuing.commitmentprover.responses.hatm_i_j_" + base.getBaseIndex();
        responses.put(URN.createZkpgsURN(hatm_i_jURN), hatm_i_j);
        proofStore.store(
            "issuing.commitmentprover.responses.hatm_i_j_" + base.getBaseIndex(), base);
      }
    }
  }

  public void computeResponsesProving() throws Exception {
    BigInteger tilder_i = (BigInteger) proofStore.retrieve(tilder_iURN);

    String C_iURN = "prover.commitments.C_" + vertex.getBaseIndex();
    GSCommitment C_i = (GSCommitment) proofStore.retrieve(C_iURN);
    BigInteger r_i = C_i.getRandomness();

    hatr_i = tilder_i.add(this.cChallenge.multiply(r_i));

    String hatr_iURN = "proving.commitmentprover.responses.hatm_i_" + vertex.getBaseIndex();

    responses.put(URN.createZkpgsURN(hatr_iURN), hatr_i );
    proofStore.store(hatr_iURN, hatr_i);

  }



  /**
   * Gets witness.
   *
   * @return the witness
   */
  public GSCommitment getWitness() {
    return witness;
  }
}
