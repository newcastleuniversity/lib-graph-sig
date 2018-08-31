package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
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
    this.baseZ = (GroupElement) proofSignature.get("proofsignature.P.baseZ");
    this.c = (BigInteger) proofSignature.get("proofsignature.P.c");
    this.baseS = (GroupElement) proofSignature.get("proofsignature.P.baseS");
    this.hatr_z = (BigInteger) proofSignature.get("proofsignature.P.hatr_Z");
    this.modN = (BigInteger) proofSignature.get("proofsignature.P.modN");
    this.baseR = (GroupElement) proofSignature.get("proofsignature.P.baseR");
    this.hatr = (BigInteger) proofSignature.get("proofsignature.P.hatr");
    this.baseR_0 = (GroupElement) proofSignature.get("proofsignature.P.baseR_0");
    this.hatr_0 = (BigInteger) proofSignature.get("proofsignature.P.hatr_0");
    this.vertexResponses = (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i");
    this.edgeResponses = (Map<URN, BigInteger>) proofSignature.get("proofsignature.P.hatr_i_j");
    //    this.graphEncodingParameters = epk.getGraphEncodingParameters();
    this.baseCollection = extendedPublicKey.getBaseCollection();
  }

  /** Check lengths. */
  @Override
  public boolean checkLengths() {
    boolean isLengthCorrect;

    int bitLength = keyGenParameters.getL_n() + keyGenParameters.getProofOffset();

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
    BigInteger hatVertexResponse;
    BigInteger hatEdgeResponse;

    Map<URN, GroupElement> hatValues = new HashMap<URN, GroupElement>();

    // Compute the negation of the challenge once.
    BigInteger negChallenge = c.negate();

    /** TODO check computation if it is computed correctly according to spec. */
    GroupElement hatZ = baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_z));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATZ)), hatZ);
    //    proofStore.store(getVerifierURN(URNType.HATZ),hatZ );

    GroupElement hatR = baseR.modPow(negChallenge).multiply(baseS.modPow(hatr));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATBASER)), hatR);

    GroupElement hatR_0 = baseR_0.modPow(negChallenge).multiply(baseS.modPow(hatr_0));
    hatValues.put(URN.createZkpgsURN(getVerifierURN(URNType.HATBASER0)), hatR_0);

    GroupElement hatR_i;
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
          hatR_i);
    }

    GroupElement hatR_i_j;
    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      hatEdgeResponse =
          edgeResponses.get(
              URN.createZkpgsURN(
                  getVerifierURN(URNType.HATRIJ, baseRepresentation.getBaseIndex())));
      hatR_i_j =
          baseRepresentation.getBase().modPow(negChallenge).multiply(baseS.modPow(hatEdgeResponse));
      hatValues.put(
          URN.createZkpgsURN(getVerifierURN(URNType.HATBASERIJ, baseRepresentation.getBaseIndex())),
          hatR_i_j);
    }

    return hatValues;
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
