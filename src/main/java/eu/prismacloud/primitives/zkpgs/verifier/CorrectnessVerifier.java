package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/** */
public class CorrectnessVerifier {

  private final BigInteger e;
  private final BigInteger hatd;
  private final BigInteger n_2;
  private final BigInteger v;
  private final BigInteger cPrime;
  private final BigInteger Z;
  private final BigInteger A;
  private final BigInteger S;
  private final BigInteger R_0;
  private final BigInteger m_0;
  private final BigInteger N;
  private final Map<URN, BaseRepresentation> encodedVertices;
  private final Map<URN, BaseRepresentation> encodedEdges;
  private final KeyGenParameters keyGenParameters;
  private BigInteger Q;
  private BigInteger R_i;
  private BigInteger R_i_j;
  private BigInteger hatQ;
  private BigInteger hatA;
  private BigInteger hatc;
  private List<BigInteger> challengeList;

  public CorrectnessVerifier(
      BigInteger e,
      BigInteger v,
      BigInteger cPrime,
      BigInteger hatd,
      BigInteger Z,
      BigInteger A,
      BigInteger S,
      BigInteger R_0,
      BigInteger m_0,
      BigInteger N,
      Map<URN, BaseRepresentation> encodedVertices,
      Map<URN, BaseRepresentation> encodedEdges,
      BigInteger n_2,
      KeyGenParameters keyGenParameters) {

    checkE(e);
    this.e = e;
    this.v = v;
    this.cPrime = cPrime;
    this.hatd = hatd;
    this.Z = Z;
    this.A = A;
    this.S = S;
    this.R_0 = R_0;
    this.m_0 = m_0;
    this.N = N;
    this.encodedVertices = encodedVertices;
    this.encodedEdges = encodedEdges;
    this.n_2 = n_2;
    this.keyGenParameters = keyGenParameters;
  }

  private void checkE(BigInteger e) {
    if (!e.isProbablePrime(80)) {
      throw new IllegalArgumentException("e is not prime");
    }
    BigInteger min = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
    BigInteger max =
        min.add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_prime_e() - 1));

    if ((e.compareTo(min) < 0) || (e.compareTo(max) > 0)) {
      throw new IllegalArgumentException("e is not within range");
    }
  }

  public void computeQ() {
    for (BaseRepresentation encodedVertex : encodedVertices.values()) {
      R_i = R_i.multiply(encodedVertex.getBase().modPow(encodedVertex.getExponent(), N).getValue());
    }

    for (BaseRepresentation encodedEdge : encodedEdges.values()) {
      R_i_j = R_i_j.multiply(encodedEdge.getBase().modPow(encodedEdge.getExponent(), N).getValue());
    }

    BigInteger invertible =
        S.modPow(v, N).multiply(R_0.modPow(m_0, N)).multiply(R_i).multiply(R_i_j).mod(N);
    Q = Z.multiply(invertible.modInverse(N)).mod(N);
  }

  public void computehatQ() {
    hatQ = A.modPow(e, N);

    if (!hatQ.equals(Q)) {
      throw new IllegalArgumentException("Q is not correct");
    }
  }

  public void verifySignature() {
    hatA = A.modPow(cPrime.add(hatd.multiply(e)), N);
  }

  public void computeChallenge() {

    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(populateChallengeList(), keyGenParameters.getL_H());
  }

  public Boolean verifyChallenge() {
    return hatc.equals(cPrime);
  }

  public List<BigInteger> populateChallengeList() {
    /** TODO add context in challenge list */
    challengeList.add(Q);
    challengeList.add(A);
    challengeList.add(hatA);
    challengeList.add(n_2);

    return challengeList;
  }
}
