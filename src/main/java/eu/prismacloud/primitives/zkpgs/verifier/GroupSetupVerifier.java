package eu.prismacloud.primitives.zkpgs.verifier;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.NotImplementedException;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.Assert;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
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

  public GroupSetupVerifier(final ProofSignature proofSignature, 
		  final ExtendedPublicKey epk, final ProofStore<Object> ps) {
      
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
	  //TODO why is length reduced by 1 here?
    bitLength = computeBitLength() - 1;

    gslog.info("computeBitLength: " + bitLength);
    gslog.info("bitlength: " + this.hatr_z.bitLength());

    Assert.checkBitLength(this.hatr_z, bitLength, "length for hatr_Z is not correct ");
    Assert.checkBitLength(this.hatr, bitLength, "length for hatr is not correct ");
    Assert.checkBitLength(this.hatr_0, bitLength, "length for hatr_0 is not correct ");

    BigInteger vertexResponse;
    BigInteger edgeResponse;


    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      vertexResponse =
          this.vertexResponses.get(
              URN.createZkpgsURN(
                  "groupsetupprover.responses.hatr_i_" + baseRepresentation.getBaseIndex()));
      Assert.checkBitLength(
          vertexResponse, bitLength, "length for vertex response is not correct ");
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      edgeResponse =
          this.edgeResponses.get(
              URN.createZkpgsURN(
                  "groupsetupprover.responses.hatr_i_j_" + baseRepresentation.getBaseIndex()));
      Assert.checkBitLength(edgeResponse, bitLength, "length for edge response is not correct ");
    }
    
    // TODO switch to a model where length check returns boolean
    return true;
  }

  private int computeBitLength() {
    return keyGenParameters.getL_n()
        + keyGenParameters.getL_statzk()
        + keyGenParameters.getL_H()
        + 1;
  }

  /** Compute hat values. */
  private void computeHatValues() {
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

    /** TODO check computation if it is computed correctly according to spec. */
    hatZ = baseZ.modPow(negChallenge).multiply(baseS.modPow(hatr_z));
    hatR = baseR.modPow(negChallenge).multiply(baseS.modPow(hatr));
    hatR_0 = baseR_0.modPow(negChallenge).multiply(baseS.modPow(hatr_0));


    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      hatVertexResponse =
          vertexResponses.get(
              URN.createZkpgsURN(
                  "groupsetupprover.responses.hatr_i_" + baseRepresentation.getBaseIndex()));
      hatR_i =
          baseRepresentation
              .getBase()
              .modPow(negChallenge)
              .multiply(baseS.modPow(hatVertexResponse));

      hatVertexBases.put(
          URN.createZkpgsURN(
              "groupsetupverifier.vertex.hatR_i_" + baseRepresentation.getBaseIndex()),
          hatR_i);
    }


    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      hatEdgeResponse =
          edgeResponses.get(
              URN.createZkpgsURN(
                  "groupsetupprover.responses.hatr_i_j_" + baseRepresentation.getBaseIndex()));
      hatR_i_j =
          baseRepresentation.getBase().modPow(negChallenge).multiply(baseS.modPow(hatEdgeResponse));
      hatEdgeBases.put(
          URN.createZkpgsURN(
              "groupsetupverifier.edge.hatR_i_j_" + baseRepresentation.getBaseIndex()),
          hatR_i_j);
    }
  }

  /**
   * Compute verification challenge.
   *
   * @throws NoSuchAlgorithmException the no such algorithm exception
   */
  // TODO should be part of an orchestrator
  public void computeVerificationChallenge() throws NoSuchAlgorithmException {
    List<String> ctxList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */
    GSContext gsContext =
        new GSContext(extendedPublicKey);
    List<String> ctxList = gsContext.computeChallengeContext();

    ctxList.add(String.valueOf(hatZ));
    ctxList.add(String.valueOf(hatR));
    ctxList.add(String.valueOf(hatR_0));

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      ctxList.add(
          String.valueOf(
              hatVertexBases.get(
                  URN.createZkpgsURN(
                      "groupsetupverifier.vertex.hatR_i_" + baseRepresentation.getBaseIndex()))));
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      ctxList.add(
          String.valueOf(
              hatEdgeBases.get(
                  URN.createZkpgsURN(
                      "groupsetupverifier.edge.hatR_i_j_" + baseRepresentation.getBaseIndex()))));
    }

    return ctxList;
  }

  /** Verify challenge. */
  //  @Override
  public void verifyChallenge() throws VerificationException {
    if (!hatc.equals(c)) {
      throw new VerificationException("Challenge is rejected ");
    }
  }
  
  public GroupElement executeVerification(BigInteger cChallenge) throws ProofStoreException {
	  checkLengths();
	  computeHatValues();
	  
	  // TODO adapt interfaces to allow to return multiple group elements.
	  return null;
  }
  
  public boolean isSetupComplete() {
	  // Class cannot be instantiated without complete setup;
	  return true;
  }
  
  public List<URN> getGovernedURNs() {
	  throw new NotImplementedException("Part of the new prover interface not implemented, yet.");
  }
}
