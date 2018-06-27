package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import java.math.BigInteger;
import java.util.List;

/** */
public class CorrectnessProver { //implements IProver {

  private BigInteger n_2;
  private ProofStore<Object> proofStore;
  private ExtendedPublicKey extendedPublicKey;
  private BigInteger order;
  private KeyGenParameters keyGenParameters;
  private BigInteger tilded;
  private BigInteger tildeA;
  private List<BigInteger> challengeList;
  private BigInteger cPrime;
  private BigInteger hatd;
  private GSSignature gsSignature;
  private BigInteger modN;
  private BigInteger d;
  private BigInteger Q;
  private BigInteger A;

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

    tilded =
        CryptoUtilsFacade.computeRandomNumber(
            NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));

    proofStore.store("correctnessprover.randomness.tilded", tilded);
    tildeA = Q.modPow(tilded, modN);

    return tildeA;
  }

  public BigInteger computeChallenge() {
    challengeList = populateChallengeList();
    cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
    return cPrime;
  }

  private List<BigInteger> populateChallengeList() {
    // TODO add context list
    challengeList.add(Q);
    challengeList.add(A);
    challengeList.add(tildeA);
    challengeList.add(n_2);
    return challengeList;
  }

//  @Override
  public void computeResponses() {
    hatd = tilded.subtract(cPrime.multiply(d).mod(order));
  }

  public BigInteger postChallengePhase() {
    hatd = tilded.subtract(cPrime.multiply(d).mod(order));
    return hatd;
  }
}
