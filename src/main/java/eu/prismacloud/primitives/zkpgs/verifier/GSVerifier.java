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

public class GSVerifier  {

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
