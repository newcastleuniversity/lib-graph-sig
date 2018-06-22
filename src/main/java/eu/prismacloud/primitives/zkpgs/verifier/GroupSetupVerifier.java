package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Class represents the verification stage for the group setup. */
public class GroupSetupVerifier implements IVerifier {

  private final ProofSignature proofSignature;
  private final KeyGenParameters keyGenParameters;
  private int bitLength;
  private BigInteger hatZ;
  private BigInteger hatR;
  private BigInteger hatR_0;
  private Map<String, BigInteger> hatVertexBases;
  private Map<String, BigInteger> hatEdgeBases;
  private Map<String, BigInteger> vertexBases;
  private Map<String, BigInteger> edgeBases;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private List<BigInteger> challengeList = new ArrayList<>();
  private final BigInteger Z;
  private final BigInteger c;
  private final BigInteger S;
  private final BigInteger hatr_z;
  private final BigInteger N;
  private final BigInteger R;
  private final BigInteger hatr;
  private final BigInteger R_0;
  private final BigInteger hatr_0;
  private BigInteger hatc;

  public GroupSetupVerifier(ProofSignature proofSignature, KeyGenParameters keyGenParameters) {

    this.proofSignature = proofSignature;
    this.keyGenParameters = keyGenParameters;
    this.Z = proofSignature.getZ();
    this.c = proofSignature.getC();
    this.S = proofSignature.getS();
    this.hatr_z = proofSignature.getHatr_Z();
    this.N = proofSignature.getN();
    this.R = proofSignature.getR();
    this.hatr = proofSignature.getHatr();
    this.R_0 = proofSignature.getR_0();
    this.hatr_0 = proofSignature.getHatr_0();
    this.vertexBases = proofSignature.getVertexBases();
    this.edgeBases = proofSignature.getEdgeBases();
  }

  @Override
  public void checkLengths() {
    bitLength = computeBitLength();
    Assert.checkBitLength(
        this.proofSignature.getHatr_Z(), bitLength, "length for hatr_Z is not correct ");
    Assert.checkBitLength(
        this.proofSignature.getHatr(), bitLength, "length for hatr is not correct ");
    Assert.checkBitLength(
        this.proofSignature.getHatr_0(), bitLength, "length for hatr_0 is not correct ");
    Map<String, BigInteger> edgeResponses = proofSignature.getEdgeResponses();
    Map<String, BigInteger> vertexResponses = proofSignature.getVertexResponses();
    BigInteger vertexResponse;
    BigInteger edgeResponse;

    for (int i = 1; i <= vertexResponses.size(); ++i) {
      vertexResponse = vertexResponses.get("hatr_" + i);
      Assert.checkBitLength(
          vertexResponse, bitLength, "length for vertex hatr_" + i + " is not correct ");
    }

    for (int j = 1; j <= vertexResponses.size(); ++j) {
      edgeResponse = edgeResponses.get("hatr_" + j);
      Assert.checkBitLength(
          edgeResponse, bitLength, "length for edge hatr_" + j + " is not correct ");
    }
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  @Override
  public void computeHatValues() {
    BigInteger vertexBase;
    BigInteger edgeBase;
    BigInteger hatVertexResponse;
    BigInteger hatEdgeResponse;
    BigInteger hatR_i;
    BigInteger hatR_j;

    /** TODO check computation if it computed correctly according to spec. */
    hatZ = Z.modInverse(c).multiply(S.modPow(hatr_z, N));
    hatR = R.modInverse(c).multiply(S.modPow(hatr, N));
    hatR_0 = R_0.modInverse(c).multiply(S.modPow(hatR_0, N));

    computeGraphHatValues(vertexBases, vertexResponses, hatVertexBases);

    computeGraphHatValues(edgeBases, edgeResponses, hatEdgeBases);
  }

  private void computeGraphHatValues(
      Map<String, BigInteger> bases,
      Map<String, BigInteger> responses,
      Map<String, BigInteger> hatBases) {
    BigInteger edgeBase;
    BigInteger hatEdgeResponse;
    BigInteger hatR;
    for (int i = 1; i <= bases.size(); i++) {
      edgeBase = bases.get("R_" + i);
      hatEdgeResponse = responses.get("hatr_" + i);
      hatR = edgeBase.modInverse(c).multiply(S.modPow(hatEdgeResponse, N));
      hatBases.put("hatR_" + i, hatR);
    }
  }

  @Override
  public void computeVerificationChallenge() {
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<BigInteger> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    challengeList.add(N);
    challengeList.add(S);
    challengeList.add(Z);
    challengeList.add(R);
    challengeList.add(R_0);

    for (int i = 1; i <= vertexBases.size(); i++) {
      challengeList.add(vertexBases.get("R_" + i));
    }

    for (int j = 1; j <= edgeBases.size(); j++) {
      challengeList.add(edgeBases.get("R_" + j));
    }

    challengeList.add(hatZ);
    challengeList.add(hatR);
    challengeList.add(hatR_0);

    for (int i = 1; i <= hatVertexBases.size(); i++) {
      challengeList.add(hatVertexBases.get("tildeR_" + i));
    }

    for (int j = 1; j <= hatEdgeBases.size(); j++) {
      challengeList.add(hatEdgeBases.get("tildeR_" + j));
    }
    return challengeList;
  }

  @Override
  public void verifyChallenge() {
    if (!hatc.equals(c)) {
      throw new IllegalArgumentException("Challenge is rejected ");
    }
  }
}
