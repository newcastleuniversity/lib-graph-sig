package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** The type Commitment verifier. */
public class CommitmentVerifier {

  private final BigInteger hatvPrime;
  private final BigInteger hatm_0;
  private final ICommitment U;
  private final Map<String, BigInteger> vertexResponses;
  private final Map<String, BigInteger> edgeResponses;
  private final BigInteger c;
  private GroupElement baseS;
  private GroupElement baseZ;
  private GroupElement baseR_0;
  private BigInteger S;
  private BigInteger Z;
  private BigInteger R_0;
  private final BigInteger n_1;
  private BigInteger modN;
  private Map<URN, BaseRepresentation> bases;
  private BigInteger N;
  private Map<String, BigInteger> vertexBases;
  private Map<String, BigInteger> edgeBases;
  private final KeyGenParameters keyGenParameters;
  private BigInteger hatU;
  private List<BigInteger> challengeList;
  private BigInteger hatc;

  /**
   * Instantiates a new Commitment verifier.
   *
   * @param hatvPrime the hatv prime
   * @param hatm_0 the hatm 0
   * @param U the U
   * @param c the c
   * @param baseS the s
   * @param baseZ the z
   * @param baseR_0 the r 0
   * @param n_1 the n 1
   * @param modN the n
   * @param vertexBases the vertex bases
   * @param edgeBases the edge bases
   * @param vertexResponses the vertex responses
   * @param edgeResponses the edge responses
   * @param keyGenParameters the key gen parameters
   */
  public CommitmentVerifier(
      BigInteger hatvPrime,
      BigInteger hatm_0,
      ICommitment U,
      BigInteger c,
      BigInteger baseS,
      BigInteger baseZ,
      BigInteger baseR_0,
      BigInteger n_1,
      BigInteger modN,
      Map<String, BigInteger> vertexBases,
      Map<String, BigInteger> edgeBases,
      Map<String, BigInteger> vertexResponses,
      Map<String, BigInteger> edgeResponses,
      KeyGenParameters keyGenParameters) {
    this.U = U;
    this.c = c;
    this.S = baseS;
    this.Z = baseZ;
    this.R_0 = baseR_0;
    this.n_1 = n_1;
    this.N = modN;
    this.vertexBases = vertexBases;
    this.edgeBases = edgeBases;
    this.keyGenParameters = keyGenParameters;

    checkLengths(hatvPrime, hatm_0, vertexResponses, edgeResponses, keyGenParameters);

    this.hatvPrime = hatvPrime;
    this.hatm_0 = hatm_0;
    this.vertexResponses = vertexResponses;
    this.edgeResponses = edgeResponses;
  }

  public CommitmentVerifier(
      BigInteger hatvPrime,
      BigInteger hatm_0,
      ICommitment U,
      BigInteger c,
      GroupElement baseS,
      GroupElement baseZ,
      GroupElement baseR_0,
      BigInteger n_1,
      BigInteger modN,
      Map<URN, BaseRepresentation> bases,
      Map<String, BigInteger> vertexResponses,
      Map<String, BigInteger> edgeResponses,
      KeyGenParameters keyGenParameters) {

    this.hatvPrime = hatvPrime;
    this.hatm_0 = hatm_0;
    this.U = U;
    this.c = c;
    this.baseS = baseS;
    this.baseZ = baseZ;
    this.baseR_0 = baseR_0;
    this.n_1 = n_1;
    this.modN = modN;
    this.bases = bases;
    this.vertexResponses = vertexResponses;
    this.edgeResponses = edgeResponses;
    this.keyGenParameters = keyGenParameters;
  }

  private void checkLengths(
      BigInteger hatvPrime,
      BigInteger hatm_0,
      Map<String, BigInteger> vertexResponses,
      Map<String, BigInteger> edgeResponses,
      KeyGenParameters keyGenParameters) {

    int hatvPrimeLength =
        keyGenParameters.getL_n()
            + (2 * keyGenParameters.getL_statzk())
            + keyGenParameters.getL_H()
            + 1;
    Assert.checkBitLength(hatvPrime, hatvPrimeLength, "length of hatvPrime is not correct ");

    int messageLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 2;
    Assert.checkBitLength(hatm_0, messageLength, "length of hatm_0 is not correct ");

    for (BigInteger vertexResponse : vertexResponses.values()) {
      Assert.checkBitLength(vertexResponse, messageLength, "vertex response length is not correct");
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      Assert.checkBitLength(edgeResponse, messageLength, "edge response length is not correct");
    }
  }

  /** Computehat U. */
  public void computehatU() {

    List<BigInteger> exponents = new ArrayList<>();
    List<BigInteger> bases = new ArrayList<>();

    populateExponents(exponents);

    populateBases(bases);

    hatU =                                         
        U.getCommitment()
            .modInverse(c)
            .multiply(CryptoUtilsFacade.computeMultiBaseEx(exponents, bases, N));
  }

  /** Compute challenge. */
  public void computeChallenge() {
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<BigInteger> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    challengeList.add(N);
    challengeList.add(S);
    challengeList.add(Z);
    challengeList.add(R_0);

    for (int i = 1; i <= vertexBases.size(); i++) {
      challengeList.add(vertexBases.get("R_" + i));
    }

    for (int j = 1; j <= edgeBases.size(); j++) {
      challengeList.add(edgeBases.get("R_" + j));
    }

    challengeList.add(U.getCommitment());
    challengeList.add(hatU);
    challengeList.add(n_1);

    return challengeList;
  }

  /**
   * Verify challenge boolean.
   *
   * @return the boolean
   */
  public Boolean verifyChallenge() {
    return hatc.equals(c);
  }

  private void populateBases(List<BigInteger> bases) {
    bases.add(S);
    bases.add(R_0);

    for (BigInteger vertexBase : vertexBases.values()) {
      bases.add(vertexBase);
    }

    for (BigInteger edgeBase : edgeBases.values()) {
      bases.add(edgeBase);
    }
  }

  private void populateExponents(List<BigInteger> exponents) {
    exponents.add(hatvPrime);
    exponents.add(hatm_0);
    for (BigInteger vertexResponse : vertexResponses.values()) {
      exponents.add(vertexResponse);
    }

    for (BigInteger edgeResponse : edgeResponses.values()) {
      exponents.add(edgeResponse);
    }
  }
}
