package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** The type Commitment prover. */
public class CommitmentProver implements IProver, Storable {

  private final ProofStore<Object> proverStore;
  private Map<URN, BaseRepresentation> vertices;
  private final BaseRepresentation vertex;
  //  private final BigInteger tildem_i;
  private final ExtendedPublicKey extendedPublicKey;
  private final KeyGenParameters keyGenParameters;
  private final Map<URN, BigInteger> witnessRandomness = new HashMap<>();
  private Map<URN, BigInteger> messagesRandomness = new HashMap<>();
  private final Map<URN, BigInteger> witnesses = new HashMap<>();
  private final BigInteger N;
  private final BigInteger S;
  private BigInteger tildeC_i;
  private BigInteger tilder_i;
  private BigInteger R_i;
  private GSCommitment witness;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private String tilder_iURN;
  private BigInteger c;
  private BigInteger hatr_i;

  /**
   * Instantiates a new Commitment prover.
   *
   * @param vertex the vertex
   * @param proverStore the prover store
   * @param extendedPublicKey the extended public key
   * @param keyGenParameters the key gen parameters
   */
  public CommitmentProver(
      BaseRepresentation vertex,
      ProofStore<Object> proverStore,
      ExtendedPublicKey extendedPublicKey,
      KeyGenParameters keyGenParameters) {

    Assert.notNull(vertex, "vertex must not be null");
    Assert.notNull(proverStore, "store must not be null");
    Assert.notNull(extendedPublicKey, "extended public key must not be null");
    Assert.notNull(keyGenParameters, "keygen parameters must not be null");

    this.vertex = vertex;
    this.proverStore = proverStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.N = extendedPublicKey.getPublicKey().getModN();
    this.S = extendedPublicKey.getPublicKey().getBaseS().getValue();
  }

  @Override
  public void createWitnessRandomness() {

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
      proverStore.store(tilder_iURN, tilder_i);
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
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
  public void computeWitness() {

    /** TODO retrieve witness randomness of committed messages from the common store */
    String tildem_i_iURN = "possessionprover.witnesses.randomness.tildem_" + vertex.getBaseIndex();
    BigInteger tildem_i = (BigInteger) proverStore.retrieve(tildem_i_iURN);

    R_i = vertex.getBase().getValue();
    tildeC_i = R_i.modPow(tildem_i, N).multiply(S.modPow(tilder_i, N));
    witness = new GSCommitment(R_i, tildem_i, tilder_i, S, N);
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
  public void computeChallenge() {}

  @Override
  public void computeResponses() {
    BigInteger tilder_i = (BigInteger) proverStore.retrieve(tilder_iURN);

    String C_iURN = "prover.commitments.C_" + vertex.getBaseIndex();
    GSCommitment C_i = (GSCommitment) proverStore.retrieve(C_iURN);
    BigInteger r_i = C_i.getRandomness();

    hatr_i = tilder_i.add(this.c.multiply(r_i));
  }

  /**
   * Gets hatr i.
   *
   * @return the hatr i
   */
  public BigInteger getHatr_i() {
    return this.hatr_i;
  }

  @Override
  public void store(URN urn, ProofObject proofObject) {}

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
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
