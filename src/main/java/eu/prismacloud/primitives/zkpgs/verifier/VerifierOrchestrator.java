package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class VerifierOrchestrator {

  private final ProofSignature P_3;
  private final GSVerifier verifier;
  private final ExtendedPublicKey extendedPublicKey;
  private final KeyGenParameters keyGenParameters;
  private ProofStore<Object> verifierStore = new ProofStore<Object>();
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public VerifierOrchestrator(
      ProofSignature P_3, ExtendedPublicKey extendedPublicKey, KeyGenParameters keyGenParameters) {

    this.P_3 = P_3;
    this.verifier = new GSVerifier(verifierStore, keyGenParameters);
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
  }

  public void checkLengths(ProofSignature P_3) {
    verifier.checkLengths(P_3);
  }

  public void populateStore() {
    String ZURN = "verifier.Z";
    String APrimeURN = "verifier.APrime";
    String cURN = "verifier.c";
    String C_iURN = "verifier.C_i";
    String hatvURN = "verifier.hatv";

    try {
      verifierStore.store(cURN, P_3.get("proofsignature.P_3.c"));
      verifierStore.store(ZURN, extendedPublicKey.getPublicKey().getBaseZ());
      verifierStore.store(APrimeURN, P_3.get("proofsignature.P_3.APrime"));
      /** TODO check storage of C_i */
      verifierStore.store(C_iURN, P_3.get("proofsignature.P_3.C_i"));
    } catch (Exception e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }
}
