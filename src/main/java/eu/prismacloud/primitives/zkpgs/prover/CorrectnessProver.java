package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/** */
public class CorrectnessProver implements IProver {

  private BigInteger n_2;
  private ProofStore<Object> proofStore;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger order;
  private KeyGenParameters keyGenParameters;
  private BigInteger tilded;
  private BigInteger tildeA;
  private List<String> challengeList;
  private BigInteger cPrime;
  private BigInteger hatd;
  private GSSignature gsSignature;
  private BigInteger modN;
  private BigInteger d;
  private BigInteger Q;
  private BigInteger A;
  private Logger gslog = GSLoggerConfiguration.getGSlog();

  public BigInteger preChallengePhase(
      final GSSignature gsSignature,
      final BigInteger order,
      final BigInteger n_2,
      final ProofStore<Object> proofStore,
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters)
      throws Exception {

    this.gsSignature = gsSignature;
    this.n_2 = n_2;
    this.order = order;
    this.proofStore = proofStore;
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.tilded =
        CryptoUtilsFacade.computeRandomNumber(
            NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));
    this.Q = (BigInteger) proofStore.retrieve("issuing.signer.Q");
    this.A = (BigInteger) proofStore.retrieve("issuing.signer.A");
    this.d = (BigInteger) proofStore.retrieve("issuing.signer.d");;
    proofStore.store("correctnessprover.randomness.tilded", tilded);
    tildeA = Q.modPow(tilded, modN);

    return tildeA;
  }

  @Override
  public void createWitnessRandomness() throws ProofStoreException {

  }

  @Override
  public void computeWitness() throws ProofStoreException {

  }

  public BigInteger computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    return cPrime;
  }

  @Override
  public void computeResponses() {

  }

  private List<String> populateChallengeList() {
    challengeList = new ArrayList<String>();
//    this.Q = (BigInteger) proofStore.retrieve("issuing.signer.Q");
//    this.A = (BigInteger) proofStore.retrieve("issuing.signer.A");
//    gslog.info("Q: " + Q);
//    gslog.info("A: " + A);

    // TODO add context list
    challengeList.add(String.valueOf(Q));
    challengeList.add(String.valueOf(A));
    challengeList.add(String.valueOf(tildeA));
    challengeList.add(String.valueOf(n_2));
    return challengeList;
  }

  public BigInteger postChallengePhase() {
    hatd = tilded.subtract(cPrime.multiply(d).mod(order));
    return hatd;
  }
}
