package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.IProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSVerifier implements IProver, Storable {

  private final Map<URN, BigInteger> barV = new HashMap<>();
  private final ProofStore<Object> verifierStore;
  private final KeyGenParameters keyGenParameters;

  public GSVerifier(ProofStore<Object> verifierStore, KeyGenParameters keyGenParameters) {
    this.verifierStore = verifierStore;
    this.keyGenParameters = keyGenParameters;
  }



  public Map<URN, BigInteger> getBarV() {
    return barV;
  }

  @Override
  public void createWitnessRandomness() {}

  @Override
  public void computeWitness() {}

  @Override
  public void computeChallenge() {}

  @Override
  public void computeResponses() {}

  @Override
  public void store(URN urn, ProofObject proofObject) {}

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
  }

  public void checkLengths(ProofSignature p_3) {
    int hateLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    int hatvLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
  }
}
