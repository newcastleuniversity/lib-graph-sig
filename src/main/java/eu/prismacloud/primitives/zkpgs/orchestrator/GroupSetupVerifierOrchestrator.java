package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
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
import eu.prismacloud.primitives.zkpgs.verifier.GroupSetupVerifier;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class GroupSetupVerifierOrchestrator implements IVerifierOrchestrator {
  private final ProofStore<Object> proofStore;
  private final KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private final ExtendedPublicKey extendedPublicKey;
  private final BaseCollection baseCollection;
  private final GroupSetupVerifier gsVerifier;
  private final ProofSignature proofSignature;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private List<String> challengeList = new ArrayList<>();
  private BigInteger cChallenge;
  private Map<URN, BigInteger> responses;
  private BigInteger tilder_i;
  private BigInteger tilder_j;
  private BigInteger hatc;
  private QRElement baseZ;
  private BigInteger c;
  private QRElement baseS;
  private BigInteger hatr_z;
  private BigInteger modN;
  private QRElement baseR;
  private BigInteger hatr;
  private QRElement baseR_0;
  private BigInteger hatr_0;
  private Map<URN, BigInteger> vertexResponses;
  private Map<URN, BigInteger> edgeResponses;
  private Map<URN, GroupElement> hatValues;

  public GroupSetupVerifierOrchestrator(
      final ProofSignature proofSignature,
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore) {
    Assert.notNull(proofSignature, "Proof signature must not be null");
    Assert.notNull(extendedPublicKey, "Extended public key must not be null");
    Assert.notNull(proofStore, "Proof store must not be null");
    this.proofSignature = proofSignature;
    this.extendedPublicKey = extendedPublicKey;
    this.proofStore = proofStore;
    this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
    this.graphEncodingParameters = extendedPublicKey.getGraphEncodingParameters();
    this.gsVerifier = new GroupSetupVerifier(proofSignature, extendedPublicKey, proofStore);
    this.baseCollection = extendedPublicKey.getBaseCollection();
  }

  @Override
  public void init() {

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
  }

  @Override
  public boolean executeVerification(BigInteger cChallenge) {
    this.cChallenge = cChallenge;

    if (!checkLengths()) {
      gslog.log(Level.SEVERE, "Length checks on inputs failed");
      return false;
    }

    /** TODO return map of group elements */
    hatValues = gsVerifier.executeVerification(cChallenge);
    // gsVerifier.executeVerification(cChallenge);

    try {
      return verifyChallenge();
    } catch (VerificationException e) {
      gslog.log(Level.SEVERE, "Verification failed.", e);
      return false;
    }
  }

  private boolean verifyChallenge() throws VerificationException {
    if (!this.cChallenge.equals(hatc)) {
      throw new VerificationException("challenge verification failed");
    }
    return true;
  }

  @Override
  public BigInteger computeChallenge() throws ProofStoreException {
    gslog.info("compute challenge ");
    List<String> ctxList = populateChallengeList();
    try {
      hatc = CryptoUtilsFacade.computeHash(ctxList, keyGenParameters.getL_H());
    } catch (NoSuchAlgorithmException e) {
      gslog.log(Level.SEVERE, "Could not find the hash algorithm.", e);
      return null;
    }
    return hatc;
  }

  private List<String> populateChallengeList() {
    GSContext gsContext = new GSContext(extendedPublicKey);
    List<String> ctxList = gsContext.computeChallengeContext();

    GroupElement hatZ =
        (GroupElement) hatValues.get(URN.createZkpgsURN("groupsetupprover.responses.hatZ"));
    GroupElement hatR =
        (GroupElement) hatValues.get(URN.createZkpgsURN("groupsetupprover.responses.hatR"));
    GroupElement hatR_0 =
        (GroupElement) hatValues.get(URN.createZkpgsURN("groupsetupprover.responses.hatR_0"));

    ctxList.add(String.valueOf(hatZ));
    ctxList.add(String.valueOf(hatR));
    ctxList.add(String.valueOf(hatR_0));

    BaseIterator vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    for (BaseRepresentation baseRepresentation : vertexIterator) {
      ctxList.add(
          String.valueOf(
              hatValues.get(
                  URN.createZkpgsURN(
                      "groupsetupverifier.vertex.hatR_i_" + baseRepresentation.getBaseIndex()))));
    }

    BaseIterator edgeIterator = baseCollection.createIterator(BASE.EDGE);
    for (BaseRepresentation baseRepresentation : edgeIterator) {
      ctxList.add(
          String.valueOf(
              hatValues.get(
                  URN.createZkpgsURN(
                      "groupsetupverifier.edge.hatR_i_j_" + baseRepresentation.getBaseIndex()))));
    }

    return ctxList;
  }

  @Override
  public boolean checkLengths() {
    return gsVerifier.checkLengths();
  }
}
