package eu.prismacloud.primitives.zkpgs.prover;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofObject;
import eu.prismacloud.primitives.zkpgs.store.Storable;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.List;

/** */
public class CorrectnessProver implements IProver, Storable {

  private final BigInteger A;
  private final BigInteger Q;
  private final BigInteger d;
  private final BigInteger N;
  private final BigInteger n_2;
  private final BigInteger order;
  private final KeyGenParameters keyGenParameters;
  private BigInteger tilded;
  private BigInteger tildeA;
  private List<BigInteger> challengeList;
  private BigInteger cPrime;
  private BigInteger hatd;

  public CorrectnessProver(
      BigInteger A,
      BigInteger Q,
      BigInteger d,
      BigInteger N,
      BigInteger n_2,
      BigInteger order,
      KeyGenParameters keyGenParameters) {

    this.A = A;
    this.Q = Q;
    this.d = d;
    this.N = N;
    this.n_2 = n_2;
    this.order = order;
    this.keyGenParameters = keyGenParameters;
  }

  @Override
  public void createWitnessRandomness() {
    tilded =
        CryptoUtilsFacade.computeRandomNumber(
            NumberConstants.TWO.getValue(), order.subtract(BigInteger.ONE));
  }

  @Override
  public void computeWitness() {
    tildeA = Q.modPow(tilded, N);
  }

  @Override
  public void computeChallenge() {
    challengeList = populateChallengeList();
    cPrime = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<BigInteger> populateChallengeList() {
    // TODO add context list
    challengeList.add(Q);
    challengeList.add(A);
    challengeList.add(tildeA);
    challengeList.add(n_2);
    return challengeList;
  }

  @Override
  public void computeResponses() {
    hatd = tilded.subtract(cPrime.multiply(d).mod(order));
  }

  @Override
  public void store(URN urn, ProofObject proofObject) {}

  @Override
  public ProofObject retrieve(URN urn) {
    return null;
  }
}
