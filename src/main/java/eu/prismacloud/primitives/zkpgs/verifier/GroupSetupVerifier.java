package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Class represents the verification stage for the group setup. */
public class GroupSetupVerifier implements IVerifier {

  private ExtendedPublicKey extendedPublicKey;
  private ProofSignature proofSignature;
  private KeyGenParameters keyGenParameters;
  private int bitLength;
  private BigInteger hatZ;
  private BigInteger hatR;
  private BigInteger hatR_0;
  private Map<String, BigInteger> hatVertexBases;
  private Map<String, BigInteger> hatEdgeBases;
  private Map<String, BigInteger> vertexBases;
  private Map<String, BigInteger> edgeBases;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private List<String> challengeList = new ArrayList<>();
  private BigInteger Z;
  private BigInteger c;
  private BigInteger S;
  private BigInteger hatr_z;
  private BigInteger N;
  private BigInteger R;
  private BigInteger hatr;
  private BigInteger R_0;
  private BigInteger hatr_0;
  private BigInteger hatc;
  private List<String> contextList;

  public void preChallengePhase(ExtendedPublicKey extendedPublicKey, ProofSignature proofSignature, KeyGenParameters keyGenParameters, GraphEncodingParameters graphEncodingParameters) {
    this.extendedPublicKey = extendedPublicKey;
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
    this.graphEncodingParameters = graphEncodingParameters;
  }


//  @Override
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

//  @Override
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

//  @Override
  public void computeVerificationChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    contextList = GSContext.computeChallengeContext(extendedPublicKey,  keyGenParameters, graphEncodingParameters);
    challengeList.add(String.valueOf(N));
    challengeList.add(String.valueOf(S));
    challengeList.add(String.valueOf(Z));
    challengeList.add(String.valueOf(R));
    challengeList.add(String.valueOf(R_0));

    for (int i = 1; i <= vertexBases.size(); i++) {
      challengeList.add(String.valueOf(vertexBases.get("R_" + i)));
    }

    for (int j = 1; j <= edgeBases.size(); j++) {
      challengeList.add(String.valueOf(edgeBases.get("R_" + j)));
    }

    challengeList.add(String.valueOf(hatZ));
    challengeList.add(String.valueOf(hatR));
    challengeList.add(String.valueOf(hatR_0));

    for (int i = 1; i <= hatVertexBases.size(); i++) {
      challengeList.add(String.valueOf(hatVertexBases.get("tildeR_" + i)));
    }

    for (int j = 1; j <= hatEdgeBases.size(); j++) {
      challengeList.add(String.valueOf(hatEdgeBases.get("tildeR_" + j)));
    }
    return challengeList;
  }

//  @Override
  public void verifyChallenge() {
    if (!hatc.equals(c)) {
      throw new IllegalArgumentException("Challenge is rejected ");
    }
  }
}
