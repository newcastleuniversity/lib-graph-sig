package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URNType;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/** Class represents the verification stage for the group setup. */
public class GroupSetupVerifier implements IVerifier {
  public static final String URNID = "groupsetupverifier";
  private final ExtendedPublicKey extendedPublicKey;
  private final ProofSignature proofSignature;
  private final ProofStore<Object> proofStore;
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
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement hatR_i_j;
  private BaseCollection baseCollection;

  public GroupSetupVerifier(
      final ProofSignature proofSignature,
      final ExtendedPublicKey epk,
      final ProofStore<Object> ps) {
    Assert.notNull(proofSignature, "proofSignature must not be null");
    Assert.notNull(epk, "ExtendedPublicKey must not be null");
    Assert.notNull(ps, "ProofStore must not be null");

    this.extendedPublicKey = epk;
    this.proofSignature = proofSignature;
    this.proofStore = ps;
    this.keyGenParameters = epk.getKeyGenParameters();

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
    this.graphEncodingParameters = epk.getGraphEncodingParameters();
    this.baseCollection = extendedPublicKey.getBaseCollection();
  }

  /** Check lengths. */
  @Override
  public boolean checkLengths() {
    boolean isLengthCorrect;

    bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

    isLengthCorrect =
        CryptoUtilsFacade.isInPMRange(this.hatr_z, bitLength)
            && CryptoUtilsFacade.isInPMRange(this.hatr, bitLength)
            && CryptoUtilsFacade.isInPMRange(this.hatr_0, bitLength);

    BigInteger vertexResponse;
    BigInteger edgeResponse;

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      vertexResponse =
          this.vertexResponses.get(
              URN.createZkpgsURN(getVerifierURN(URNType.HATRI, baseRepresentation.getBaseIndex())));
      isLengthCorrect = isLengthCorrect && CryptoUtilsFacade.isInPMRange(vertexResponse, bitLength);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      edgeResponse =
          this.edgeResponses.get(
              URN.createZkpgsURN(
                  getVerifierURN(URNType.HATRIJ, baseRepresentation.getBaseIndex())));
      isLengthCorrect = isLengthCorrect && CryptoUtilsFacade.isInPMRange(edgeResponse, bitLength);
    }

    return isLengthCorrect;
  }

  /** Compute hat values. */
  public Map<URN, GroupElement> computeHatValues() {
    GroupElement vertexBase;
    GroupElement edgeBase;
    BigInteger hatVertexResponse;
    BigInteger hatEdgeResponse;
    GroupElement hatR_i;
    GroupElement hatR_j;

    HashMap<URN, GroupElement> hatValues = new HashMap<URN, GroupElement>();
    //    hatEdgeBases = new HashMap<URN, GroupElement>();

    // Compute the negation of the challenge once.
    BigInteger negChallenge = c.negate();

    /** TODO check computation if it is computed correctly according to spec. */
    hatZ = baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_z));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATZ)), hatZ);

    hatR = baseR.modPow(negChallenge).multiply(baseS.modPow(hatr));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATR)), hatR);

    hatR_0 = baseR_0.modPow(negChallenge).multiply(baseS.modPow(hatr_0));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATR0)), hatR_0);

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      hatVertexResponse =
          vertexResponses.get(
              URN.createZkpgsURN(getVerifierURN(URNType.HATRI, baseRepresentation.getBaseIndex())));
      hatR_i =
          baseRepresentation
              .getBase()
              .modPow(negChallenge)
              .multiply(baseS.modPow(hatVertexResponse));

      hatValues.put(
          URN.createZkpgsURN(getVerifierURN(URNType.HATBASERI, baseRepresentation.getBaseIndex())),
          //              "groupsetupverifier.vertex.hatR_i_" + baseRepresentation.getBaseIndex()),
          hatR_i);
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      hatEdgeResponse =
          edgeResponses.get(
              URN.createZkpgsURN(
                  getVerifierURN(URNType.HATRIJ, baseRepresentation.getBaseIndex())));
      //                  "groupsetupprover.responses.hatr_i_j_" +
      // baseRepresentation.getBaseIndex()));
      hatR_i_j =
          baseRepresentation.getBase().modPow(negChallenge).multiply(baseS.modPow(hatEdgeResponse));
      hatValues.put(
          URN.createZkpgsURN(getVerifierURN(URNType.HATBASERIJ, baseRepresentation.getBaseIndex())),
          //              "groupsetupverifier.edge.hatR_i_j_" + baseRepresentation.getBaseIndex()),
          hatR_i_j);
    }

    return hatValues;
  }

  //  /**
  //   * Compute verification challenge.
  //   *
  //   * @throws NoSuchAlgorithmException the no such algorithm exception
  //   */
  //  // TODO should be part of an orchestrator
  //  public void computeVerificationChallenge() throws NoSuchAlgorithmException {
  //    List<String> ctxList = populateChallengeList();
  //    hatc = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());
  //  }

  //  private List<String> populateChallengeList() {
  //    /** TODO add context to list of elements in challenge */
  //    GSContext gsContext = new GSContext(extendedPublicKey);
  //    List<String> ctxList = gsContext.computeChallengeContext();
  //
  //    ctxList.add(String.valueOf(hatZ));
  //    ctxList.add(String.valueOf(hatR));
  //    ctxList.add(String.valueOf(hatR_0));
  //
  //    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
  //    for (BaseRepresentation baseRepresentation : vertexIterator) {
  //      ctxList.add(
  //          String.valueOf(
  //              hatVertexBases.get(
  //                  URN.createZkpgsURN(
  //                      "groupsetupverifier.vertex.hatR_i_" +
  // baseRepresentation.getBaseIndex()))));
  //    }
  //
  //    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
  //    for (BaseRepresentation baseRepresentation : edgeIterator) {
  //      ctxList.add(
  //          String.valueOf(
  //              hatEdgeBases.get(
  //                  URN.createZkpgsURN(
  //                      "groupsetupverifier.edge.hatR_i_j_" +
  // baseRepresentation.getBaseIndex()))));
  //    }
  //
  //    return ctxList;
  //  }

  /** Verify challenge. */
  //  @Override
  public void verifyChallenge() throws VerificationException {
    if (!hatc.equals(c)) {
      throw new VerificationException("Challenge is rejected ");
    }
  }

  @Override
  public Map<URN, GroupElement> executeVerification(BigInteger cChallenge) {
    if (!checkLengths()) return null;
    return computeHatValues();
  }

  @Override
  public boolean isSetupComplete() {
    // Class cannot be instantiated without complete setup;
    return true;
  }

  public String getVerifierURN(URNType t) {
    if (URNType.isEnumerable(t)) {
      throw new RuntimeException(
          "URNType " + t + " is enumerable and should be evaluated with an index.");
    }
    return GroupSetupVerifier.URNID + "." + URNType.getClass(t) + "." + URNType.getSuffix(t);
  }

  public String getVerifierURN(URNType t, int index) {
    if (!URNType.isEnumerable(t)) {
      throw new RuntimeException(
          "URNType " + t + " is not enumerable and should not be evaluated with an index.");
    }
    return GroupSetupVerifier.URNID
        + "."
        + URNType.getClass(t)
        + "."
        + URNType.getSuffix(t)
        + index;
  }

  @Override
  public List<URN> getGovernedURNs() {
    throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
