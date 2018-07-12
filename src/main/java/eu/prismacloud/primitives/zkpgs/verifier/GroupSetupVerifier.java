package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Logger;

/** Class represents the verification stage for the group setup. */
public class GroupSetupVerifier implements IVerifier {

  private ExtendedPublicKey extendedPublicKey;
  private ProofSignature proofSignature;
  private ProofStore<Object> proofStore;
  private KeyGenParameters keyGenParameters;
  private int bitLength;
  private GroupElement hatZ;
  private GroupElement hatR;
  private GroupElement hatR_0;
  private Map<URN, GroupElement> hatVertexBases;
  private Map<URN, GroupElement> hatEdgeBases;
  private Map<URN, GroupElement> vertexBases;
  private Map<URN, GroupElement> edgeBases;
  private GraphEncodingParameters graphEncodingParameters;
  private Map<URN, BigInteger> vertexResponses;
  private Map<URN, BigInteger> edgeResponses;
  private List<String> challengeList = new ArrayList<>();
  private GroupElement baseZ;
  private BigInteger c;
  private GroupElement baseS;
  private BigInteger hatr_z;
  private BigInteger modN;
  private GroupElement baseR;
  private BigInteger hatr;
  private GroupElement baseR_0;
  private BigInteger hatr_0;
  private BigInteger hatc;
  private List<String> contextList;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement hatR_i_j;

  /**
   * Pre challenge phase.
   *
   * @param extendedPublicKey the extended public key
   * @param proofSignature the proof signature
   * @param proofStore the proof store
   * @param keyGenParameters the key gen parameters
   * @param graphEncodingParameters the graph encoding parameters
   */
  public void preChallengePhase(
      ExtendedPublicKey extendedPublicKey,
      ProofSignature proofSignature,
      ProofStore<Object> proofStore,
      KeyGenParameters keyGenParameters,
      GraphEncodingParameters graphEncodingParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.proofSignature = proofSignature;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;

    this.baseZ = (QRElement) proofSignature.get("proofsignature.P.baseZ");
    this.c = (BigInteger) proofSignature.get("proofsignature.P.c");
    this.baseS = (QRElement) proofSignature.get("proofsignature.P.baseS");
    this.hatr_z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    this.modN = (BigInteger) proofSignature.get("proofsignature.P.modN");
    this.baseR = (QRElement) proofSignature.get("proofsignature.P.baseR");
    this.hatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    this.baseR_0 = (QRElement) proofSignature.get("proofsignature.P.baseR_0");
    this.hatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    this.vertexResponses = (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    this.edgeResponses = (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");
    this.graphEncodingParameters = graphEncodingParameters;
  }

  /** Check lengths. */
  //  @Override
  public void checkLengths() {
    bitLength = computeBitLength() - 1;

    gslog.info("computeBitLength: " + bitLength);
    gslog.info("bitlength: " + this.hatr_z.bitLength());

    Assert.checkBitLength(this.hatr_z, bitLength, "length for hatr_Z is not correct ");
    Assert.checkBitLength(this.hatr, bitLength, "length for hatr is not correct ");
    Assert.checkBitLength(this.hatr_0, bitLength, "length for hatr_0 is not correct ");

    BigInteger vertexResponse;
    BigInteger edgeResponse;

    BaseRepresentation baseR;
    for (Entry<URN, BaseRepresentation> baseRepresentation :
        extendedPublicKey.getBases().entrySet()) {

//      gslog.info("key: " + baseRepresentation.getKey());
      baseR = baseRepresentation.getValue();
      if (baseR.getBaseType() == BASE.VERTEX) {
        vertexResponse =
            this.vertexResponses.get(
                URN.createZkpgsURN("groupsetupprover.responses.hatr_i_" + baseR.getBaseIndex()));
        Assert.checkBitLength(
            vertexResponse, bitLength, "length for vertex response is not correct ");

      } else if (baseR.getBaseType() == BASE.EDGE) {
        edgeResponse =
            this.edgeResponses.get(
                URN.createZkpgsURN("groupsetupprover.responses.hatr_i_j_" + baseR.getBaseIndex()));
        Assert.checkBitLength(edgeResponse, bitLength, "length for edge response is not correct ");
      }
    }
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  /** Compute hat values. */
  //  @Override
  public void computeHatValues() {
    GroupElement vertexBase;
    GroupElement edgeBase;
    BigInteger hatVertexResponse;
    BigInteger hatEdgeResponse;
    GroupElement hatR_i;
    GroupElement hatR_j;
   
    hatVertexBases = new HashMap<URN, GroupElement>();
    hatEdgeBases = new HashMap<URN, GroupElement>();
    
    // Compute the negation of the challenge once.
    BigInteger negChallenge = c.negate();
    
//    GroupElement checkHatZ =
//            baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_z));
//    // What is checkHatZ used for?

    /** TODO check computation if it is computed correctly according to spec. */
    hatZ = baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_z));
    hatR = baseR.modPow(negChallenge).multiply(baseS.modPow(hatr));
    hatR_0 = baseR_0.modPow(negChallenge).multiply(baseS.modPow(hatr_0));

    BaseRepresentation baseR;
    for (Entry<URN, BaseRepresentation> baseRepresentation :
        extendedPublicKey.getBases().entrySet()) {

//      gslog.info("key: " + baseRepresentation.getKey());
      baseR = baseRepresentation.getValue();
      if (baseR.getBaseType() == BASE.VERTEX) {
        hatVertexResponse =
            vertexResponses.get(
                URN.createZkpgsURN("groupsetupprover.responses.hatr_i_" + baseR.getBaseIndex()));
        hatR_i =
            baseR
                .getBase()
                .modPow(negChallenge)
                .multiply(baseS.modPow(hatVertexResponse));

        hatVertexBases.put(
            URN.createZkpgsURN("groupsetupverifier.vertex.hatR_i_" + baseR.getBaseIndex()),
            hatR_i);

      } else if (baseR.getBaseType() == BASE.EDGE) {
        hatEdgeResponse =
            edgeResponses.get(
                URN.createZkpgsURN("groupsetupprover.responses.hatr_i_j_" + baseR.getBaseIndex()));
        hatR_i_j =
            baseR.getBase().modPow(negChallenge).multiply(baseS.modPow(hatEdgeResponse));
        hatEdgeBases.put(
            URN.createZkpgsURN("groupsetupverifier.edge.hatR_i_j_" + baseR.getBaseIndex()),
            hatR_i_j);
      }
    }
  }

  /**
   * Compute verification challenge.
   *
   * @throws NoSuchAlgorithmException the no such algorithm exception
   */
  //  @Override
  public void computeVerificationChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    contextList =
        GSContext.computeChallengeContext(
            extendedPublicKey, keyGenParameters, graphEncodingParameters);
    challengeList.add(String.valueOf(modN));
    challengeList.add(String.valueOf(baseS));
    challengeList.add(String.valueOf(baseZ));
    challengeList.add(String.valueOf(baseR));
    challengeList.add(String.valueOf(baseR_0));

    for (BaseRepresentation baseRepresentation : extendedPublicKey.getBases().values()) {
      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
    }

    challengeList.add(String.valueOf(hatZ));
    challengeList.add(String.valueOf(hatR));
    challengeList.add(String.valueOf(hatR_0));

    for (BaseRepresentation baseRepresentation : extendedPublicKey.getBases().values()) {
      if (baseRepresentation.getBaseType() == BASE.VERTEX) {

        challengeList.add(
            String.valueOf(
                hatVertexBases.get(
                    URN.createZkpgsURN(
                        "groupsetupverifier.vertex.hatR_i_" + baseRepresentation.getBaseIndex()))));

      } else if (baseRepresentation.getBaseType() == BASE.EDGE) {
        challengeList.add(
            String.valueOf(
                hatEdgeBases.get(
                    URN.createZkpgsURN(
                        "groupsetupverifier.edge.hatR_i_j_" + baseRepresentation.getBaseIndex()))));
      }
    }

    return challengeList;
  }

  /** Verify challenge. */
  //  @Override
  public void verifyChallenge() {
    if (!hatc.equals(c)) {
      throw new IllegalArgumentException("Challenge is rejected ");
    }
  }
}
