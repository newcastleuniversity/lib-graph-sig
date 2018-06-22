package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GSProver implements IProver, Storable {

  private final BigInteger N;
  private final BigInteger S;
  private final BigInteger n_3;
  private final ProofStore<Object> proverStore;
  private final KeyGenParameters keyGenParameters;
  private BigInteger r;
  private Map<URN, GSCommitment> commitmentMap;
  private GSSignature blindedSignature;
  private BigInteger r_i;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public GSProver(
      BigInteger N,
      GroupElement S,
      BigInteger n_3,
      ProofStore<Object> proverStore,
      KeyGenParameters keyGenParameters) {

    this.N = N;
    this.S = S.getValue();
    this.n_3 = n_3;
    this.proverStore = proverStore;
    this.keyGenParameters = keyGenParameters;
  }

  @Override
  public void createWitnessRandomness() {}

  @Override
  public void computeWitness() {}

  @Override
  public void computeChallenge() {}

  @Override
  public void computeResponses() {}

  public Map<URN, GSCommitment> getCommitmentMap() {
    return this.commitmentMap;
  }

  public void computeCommitments(Map<URN, BaseRepresentation> vertexRepresentations)
      throws Exception {
    GSCommitment commitment;
    BigInteger R_i;
    BigInteger m_i;
    BigInteger C_i;

    this.commitmentMap = new HashMap<>();

    int i = 0;
    for (BaseRepresentation vertexRepresentation : vertexRepresentations.values()) {
      R_i = vertexRepresentation.getBase().getValue();
      /** TODO check lenght of randomness r */
      r_i = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_n());
      m_i = vertexRepresentation.getExponent();
      C_i = R_i.modPow(m_i, N).multiply(S.modPow(r, N));
      commitment = new GSCommitment(R_i, m_i, r_i, S, N);
      String commitmentURN = "prover.commitments.C_" + i;
      commitmentMap.put(
          URN.createURN(URN.getZkpgsNameSpaceIdentifier(), commitmentURN), commitment);
      proverStore.store(commitmentURN, commitment);

      i++;
    }

    String commmitmentMapURN = "prover.commitments.C_i";
    proverStore.store(commmitmentMapURN, commitmentMap);
  }

  public void computeBlindedSignature(GSSignature gsSignature) {
    blindedSignature =
        gsSignature.blind(gsSignature.getA(), gsSignature.getE(), gsSignature.getV());
    storeBlindedGS();
  }

  private void storeBlindedGS() {
    String APrimeURN = "prover.blindedgs.APrime";
    String ePrimeURN = "prover.blindedgs.ePrime";
    String vPrimeURN = "prover.blindedgs.vPrime";

    try {
      proverStore.store(APrimeURN, blindedSignature.getA());
      proverStore.store(ePrimeURN, blindedSignature.getE());
      proverStore.store(vPrimeURN, blindedSignature.getV());
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  public void computePreChallengePhase() {

    //    GSPossessionProver gsPossessionProver = new GSPossessionProver();

  }

  @Override
  public void store(URN urn, ProofObject proofObject) {
    /** TODO store public values and commitment randomness C_i, r_i */
  }

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
  }
}
