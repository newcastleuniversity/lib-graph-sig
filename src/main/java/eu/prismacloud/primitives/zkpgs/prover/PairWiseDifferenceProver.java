package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.EEAlgorithm;
import java.math.BigInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Pair wise difference prover. */
public class PairWiseDifferenceProver implements IProver {

  private BigInteger m_Bari;
  private BigInteger m_Barj;
  private BigInteger r_Bari;
  private BigInteger r_Barj;
  private KeyGenParameters keyGenParameters;
  private GSCommitment C_j;
  private GSCommitment C_i;
  private BigInteger S;
  private BigInteger modN;
  private ProofStore<Object> proverStore;
  private int index;
  private BigInteger a_BariBarj;
  private BigInteger b_BariBarj;
  private BigInteger d_BariBarj;
  private BigInteger r_BariBarj;
  private BigInteger tildea_BariBarj;
  private BigInteger tildeb_BariBarj;
  private BigInteger tilder_BariBarj;
  private BigInteger hata_BariBarj;
  private BigInteger hatb_BariBarj;
  private BigInteger hatr_BariBarj;
  private BigInteger basetildeR_BariBarj;
  private BigInteger c;
  private String a_BariBarjURN;
  private String b_BariBarjURN;
  private String r_BariBarjURN;
  private String tildea_BariBarjURN;
  private String tildeb_BariBarjURN;
  private String tilder_BariBarjURN;

  Logger gslog = GSLoggerConfiguration.getGSlog();
  private String basetildeR_BariBarjURN;

  /**
   * Instantiates a new Pair wise difference prover.
   *
   * @param C_i the c i
   * @param C_j the c j
   * @param S the s
   * @param modN the n
   * @param index the index of the pairwise difference prover component
   * @param proverStore the prover store
   * @param keyGenParameters the key gen parameters
   */
  public PairWiseDifferenceProver(
      GSCommitment C_i,
      GSCommitment C_j,
      BigInteger S,
      BigInteger modN,
      int index,
      ProofStore<Object> proverStore,
      KeyGenParameters keyGenParameters) {

    Assert.notNull(C_i, "commitment i must not be null");
    Assert.notNull(C_j, "commitment j must not be null");
    Assert.notNull(C_i.getExponents(), "commitment  message must not be null");
    Assert.notNull(C_i.getRandomness(), "commitment randomness must not be null");
    Assert.notNull(C_j.getExponents(), "commitment message must not be null");
    Assert.notNull(C_j.getRandomness(), "commitment randomness must not be null");
    Assert.notNull(index, "component prover index must not be null");
    Assert.notNull(proverStore, "Prover store must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");

    this.C_i = C_i;
    this.C_j = C_j;
    this.S = S;
    this.modN = modN;
    this.m_Bari = C_i.getExponents().get(URN.createZkpgsURN("commitment.C_i"));
    this.r_Bari = C_i.getRandomness();
    this.m_Barj = C_j.getExponents().get(URN.createZkpgsURN("commitment.C_j"));
    this.r_Barj = C_i.getRandomness();
    this.index = index;
    this.proverStore = proverStore;
    this.keyGenParameters = keyGenParameters;
  }

  public PairWiseDifferenceProver() {}

  /** Precomputation. @throws Exception the exception */
  public void precomputation() throws Exception {

    computeEEA();
    if (!d_BariBarj.equals(BigInteger.ONE)) {
      throw new IllegalArgumentException("messages are not coprime");
    }

    r_BariBarj = computeDifferentialRandomness();

    storeCoprimality();
  }

  private void storeCoprimality() throws Exception {
    a_BariBarjURN = "prover.pairwiseprover.a_BariBarj_" + index;

    b_BariBarjURN = "prover.pairwiseprover.b_BariBarj_" + index;

    r_BariBarjURN = "prover.pairwiseprover.r_BariBarj_" + index;

    proverStore.store(a_BariBarjURN, a_BariBarj);
    proverStore.store(b_BariBarjURN, a_BariBarj);
    proverStore.store(r_BariBarjURN, r_BariBarj);
  }

  /**
   * Gets r bari barj.
   *
   * @return the r bari barj
   */
  public BigInteger getR_BariBarj() {
    return this.r_BariBarj;
  }

  /**
   * Gets c j.
   *
   * @return the c j
   */
  public GSCommitment getC_j() {
    return this.C_j;
  }

  /**
   * Gets c i.
   *
   * @return the c i
   */
  public GSCommitment getC_i() {
    return this.C_i;
  }

  /**
   * Gets tildea bari barj.
   *
   * @return the tildea bari barj
   */
  public BigInteger getTildea_BariBarj() {
    return this.tildea_BariBarj;
  }

  /**
   * Gets tildeb bari barj.
   *
   * @return the tildeb bari barj
   */
  public BigInteger getTildeb_BariBarj() {
    return this.tildeb_BariBarj;
  }

  /**
   * Gets tilder bari barj.
   *
   * @return the tilder bari barj
   */
//  public BigInteger getTilder_BariBarj() {
//    return this.tilder_BariBarj;
//  }

  /** Compute eea. */
  public void computeEEA() {
    EEAlgorithm.computeEEAlgorithm(m_Bari, m_Barj);
    this.d_BariBarj = EEAlgorithm.getD();
    this.a_BariBarj = EEAlgorithm.getS();
    this.b_BariBarj = EEAlgorithm.getT();
  }

  /**
   * Compute differential randomness big integer.
   *
   * @return the big integer
   */
  public BigInteger computeDifferentialRandomness() {
    return r_Bari.negate().multiply(a_BariBarj).subtract(r_Barj.multiply(b_BariBarj));
  }

  /**
   * Gets a bari barj.
   *
   * @return the a bari barj
   */
  public BigInteger getA_BariBarj() {
    return this.a_BariBarj;
  }

  /**
   * Gets b bari barj.
   *
   * @return the b bari barj
   */
  public BigInteger getB_BariBarj() {
    return this.b_BariBarj;
  }

  /**
   * Gets d bari barj.
   *
   * @return the d bari barj
   */
  public BigInteger getD_BariBarj() {
    return this.d_BariBarj;
  }

  @Override
  public void createWitnessRandomness() {
    int randomnessLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    tildea_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);
    tildeb_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);
    tilder_BariBarj = CryptoUtilsFacade.computeRandomNumber(randomnessLength);

    storeWitnessRandomness();
  }

  private void storeWitnessRandomness() {
    tildea_BariBarjURN = "pairwiseprover.tildea_BariBarj" + index;

    tildeb_BariBarjURN = "pairwiseprover.tildeb_BariBarj" + index;

    tilder_BariBarjURN = "pairwiseprover.tilder_BariBarj" + index;
    try {
      proverStore.store(tildea_BariBarjURN, tildea_BariBarj);
      proverStore.store(tildeb_BariBarjURN, tildeb_BariBarj);
      proverStore.store(tilder_BariBarjURN, tilder_BariBarj);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  @Override
  public void computeWitness() {
    BigInteger C_Bari = C_i.getCommitmentValue();
    BigInteger C_Barj = C_j.getCommitmentValue();
    basetildeR_BariBarj =
        C_Bari.modPow(tildea_BariBarj, modN)
            .multiply(
                C_Bari.modPow(tildeb_BariBarj, modN).multiply(S.modPow(tilder_BariBarj, modN)));

    storeWitness();
  }

  private void storeWitness() {
    basetildeR_BariBarjURN = "pairwiseprover.basetildeR_BariBarj" + index;
    try {
      proverStore.store(tildea_BariBarjURN, basetildeR_BariBarj);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  @Override
  public BigInteger computeChallenge() {
    return BigInteger.ONE;
  }

  /**
   * Sets challenge.
   *
   * @param challenge the challenge
   */
  public void setChallenge(BigInteger challenge) {
    this.c = challenge;
  }

  @Override
  public void computeResponses() {
    /** TODO retrieve coprimality secrets, witness randomness */
    hata_BariBarj = tildea_BariBarj.add(this.c.multiply(a_BariBarj));
    hatb_BariBarj = tildeb_BariBarj.add(this.c.multiply(b_BariBarj));
    hatr_BariBarj = tilder_BariBarj.add(this.c.multiply(r_BariBarj));

    storeResponses();
  }

  private void storeResponses() {
    String hata_BariBarjURN = "pairwiseprover.responses.hata_BariBarj_" + index;
    String hatb_BariBarjURN = "pairwiseprover.responses.hatb_BariBarj_" + index;
    String hatr_BariBarjURN = "pairwiseprover.responses.hatr_BariBarj" + index;

    try {
      proverStore.store(hata_BariBarjURN, hata_BariBarj);
      proverStore.store(hatb_BariBarjURN, hatb_BariBarj);
      proverStore.store(hatr_BariBarjURN, hatr_BariBarj);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  /**
   * Gets hata bari barj.
   *
   * @return the hata bari barj
   */
  public BigInteger getHata_BariBarj() {
    return this.hata_BariBarj;
  }

  /**
   * Gets hatb bari barj.
   *
   * @return the hatb bari barj
   */
  public BigInteger getHatb_BariBarj() {
    return this.hatb_BariBarj;
  }

  /**
   * Gets hatr bari barj.
   *
   * @return the hatr bari barj
   */
  public BigInteger getHatr_BariBarj() {
    return this.hatr_BariBarj;
  }

  /**
   * Gets tilde r bari barj.
   *
   * @return the tilde r bari barj
   */
  public BigInteger getBasetildeR_BariBarj() {
    return basetildeR_BariBarj;
  }
}
