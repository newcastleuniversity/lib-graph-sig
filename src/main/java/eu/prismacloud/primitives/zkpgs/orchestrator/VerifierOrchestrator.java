package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.ProofStoreException;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
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
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.GSVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.PossessionVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory.VerifierType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;

/** */
public class VerifierOrchestrator {

  private BaseIterator vertexIterator;
  private BaseIterator edgeIterator;
  private ProofSignature P_3;
  private final GSVerifier verifier;
  private final ExtendedPublicKey extendedPublicKey;
  private final ProofStore<Object> proofStore;
  private final KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private ProofStore<Object> verifierStore = new ProofStore<Object>();
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement aPrime;
  private Map<URN, GSCommitment> C_i;
  private BigInteger cChallenge;
  private BigInteger hate;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private List<CommitmentVerifier> commitmentVerifierList;
  private BigInteger tildem_i;
  private BigInteger n_3;
  private List<String> contextList;
  private List<String> challengeList;
  private GroupElement hatZ;
  private BigInteger hatc;
  private BaseCollection baseCollection;

  public VerifierOrchestrator(
      final ExtendedPublicKey extendedPublicKey,
      final ProofStore<Object> proofStore,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {

    this.extendedPublicKey = extendedPublicKey;
    this.proofStore = proofStore;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.verifier = new GSVerifier(extendedPublicKey, keyGenParameters);
    //    this.vertexIterator = extendedPublicKey.getBaseCollection().createIterator(BASE.VERTEX);
    //    this.edgeIterator = extendedPublicKey.getBaseCollection().createIterator(BASE.EDGE);
  }

  public void init() {

    this.baseCollection = (BaseCollection) proofStore.retrieve("encoded.bases");
    this.vertexIterator = baseCollection.createIterator(BASE.VERTEX);
    this.edgeIterator = baseCollection.createIterator(BASE.EDGE);

    n_3 = verifier.computeNonce();
    Map<URN, Object> messageElements = new HashMap<URN, Object>();
    messageElements.put(URN.createZkpgsURN("verifier.n_3"), n_3);
    verifier.sendMessage(new GSMessage(messageElements));
  }

  public void receiveProverMessage() {
    GSMessage proverMessage = verifier.receiveMessage();
    Map<URN, Object> proverMessageElements = proverMessage.getMessageElements();

    P_3 = (ProofSignature) proverMessageElements.get(URN.createZkpgsURN("prover.P_3"));
    aPrime = (GroupElement) proverMessageElements.get(URN.createZkpgsURN("prover.APrime"));
    C_i = (Map<URN, GSCommitment>) proverMessageElements.get(URN.createZkpgsURN("prover.C_i"));

    try {
      verifyMessageElementsLength(P_3);
    } catch (ProofStoreException e) {
      gslog.log(Level.SEVERE, e.getMessage());
    }
  }

  private void verifyMessageElementsLength(ProofSignature P_3) throws ProofStoreException {
    int hateLength =
        keyGenParameters.getL_prime_e()
            + keyGenParameters.getL_statzk()
            + keyGenParameters.getL_H()
            + 1;
    int hatvLength =
        keyGenParameters.getL_v() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;
    int hatmLength =
        keyGenParameters.getL_m() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 2;
    int hatrLength =
        keyGenParameters.getL_n() + keyGenParameters.getL_statzk() + keyGenParameters.getL_H() + 1;

    Map<URN, Object> proofSignatureElements = P_3.getProofSignatureElements();
    cChallenge =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.c"));
    proofStore.store("verifier.c", cChallenge);

    aPrime =
        (GroupElement) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.APrime"));
    proofStore.store("verifier.APrime", aPrime);

    hate = (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hate"));
    gslog.info("hatelength: " + hateLength);
    gslog.info("hate bitlenggh: " + hate.bitLength());
    //    Assert.checkBitLength(hate, hateLength, "hate length is not correct");
    proofStore.store("verifier.hate", hate);

    hatvPrime =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hatvPrime"));
    gslog.info("hatvlength: " + hatvLength);
    gslog.info("hatv bitlenggh: " + hatvPrime.bitLength());
    //    Assert.checkBitLength(hatvPrime, hatvLength-1, "hatvPrime length is not correct");
    proofStore.store("verifier.hatvPrime", hatvPrime);

    hatm_0 =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_3.hatm_0"));
    //    Assert.checkBitLength(hatm_0, hatmLength - 1, "hatm_0 bitlength is not correct");
    proofStore.store("verifier.hatm_0", hatm_0);

    int baseIndex;
    String hatm_iPath = "possessionprover.responses.vertex.hatm_i_";
    String hatm_iURN;
    BigInteger hatm_i;
    for (BaseRepresentation vertexBase : vertexIterator) {
      baseIndex = vertexBase.getBaseIndex();
      hatm_iURN = hatm_iPath + baseIndex;
      hatm_i =
          (BigInteger)
              proofSignatureElements.get(
                  URN.createZkpgsURN("proofsignature.P_3.hatm_i_" + baseIndex));
      //      Assert.checkBitLength(hatm_i, hatmLength, "hatm_i length is not correct");

      proofStore.store("verifier.hatm_i_" + baseIndex, hatm_i);
    }

    String hatm_i_jURN;
    String hatm_i_jPath = "possessionprover.responses.edge.hatm_i_j_";
    String hatr_iPath = "proving.commitmentprover.responses.hatr_i_";
    String hatr_iURN;
    BigInteger hatm_i_j;
    BigInteger hatr_i;
    for (BaseRepresentation edgeBase : edgeIterator) {
      baseIndex = edgeBase.getBaseIndex();
      hatm_i_jURN = hatm_i_jPath + baseIndex;
      hatm_i_j =
          (BigInteger)
              proofSignatureElements.get(
                  URN.createZkpgsURN("proofsignature.P_3.hatm_i_j_" + baseIndex));
      Assert.checkBitLength(hatm_i_j, hatmLength, "hatm_i_j length is not correct");
      proofStore.store("verifier.hatm_i_j_" + baseIndex, hatm_i_j);

      hatr_iURN = hatr_iPath + baseIndex;
      hatr_i =
          (BigInteger)
              proofSignatureElements.get(
                  URN.createZkpgsURN("proofsignature.P_3.hatr_i_" + baseIndex));
      Assert.checkBitLength(hatr_i, hatrLength, "hatr_i length is not correct");
      proofStore.store("verifier.hatr_i_" + baseIndex, hatr_i);
    }

    /** TODO extract proof signature elements from pair wise difference prover */
    populateStore(P_3);
  }

  public void preChallengePhase() {

    PossessionVerifier possessionVerifier =
        (PossessionVerifier) VerifierFactory.newVerifier(VerifierType.PossessionVerifier);

    hatZ = possessionVerifier.computeHatZ(extendedPublicKey, proofStore, keyGenParameters);

    // computeCommitmentVerifiers();
  }

  public void computeChallenge() throws NoSuchAlgorithmException {
    gslog.info("compute challenge ");
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  public void verifyChallenge() throws VerificationException {
    if (!cChallenge.equals(hatc)) {
      throw new VerificationException("challenge verification failed");
    }
  }

  private List<String> populateChallengeList() {
    challengeList = new ArrayList<>();

    GSContext gsContext =
        new GSContext(extendedPublicKey, keyGenParameters, graphEncodingParameters);
    //    contextList = gsContext.computeChallengeContext();
    //
    //    challengeList.addAll(contextList);
    challengeList.add(String.valueOf(aPrime));
    // challengeList.add(String.valueOf(extendedPublicKey.getPublicKey().getBaseZ().getValue()));

    //    for (GSCommitment gsCommitment : C_i.values()) {
    //      challengeList.add(String.valueOf(gsCommitment.getCommitmentValue()));
    //    }

    challengeList.add(String.valueOf(hatZ));

    //    BigInteger commitmentValue;
    //    String hatC_iURN;
    //    for (BaseRepresentation vertex : vertexIterator) {
    //      hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();
    //      commitmentValue = (BigInteger) proofStore.retrieve(hatC_iURN);
    //      challengeList.add(String.valueOf(commitmentValue));
    //    }

    /** TODO add pair-wise elements for challenge */
    //    for (GroupElement witness : pairWiseWitnesses.values()) {
    //      challengeList.add(String.valueOf(witness));
    //    }
    gslog.info("n3: " + n_3);
    challengeList.add(String.valueOf(n_3));

    return challengeList;
  }

  private void computeCommitmentVerifiers() {
    CommitmentVerifier commitmentVerifier;
    commitmentVerifierList = new ArrayList<>();

    String witnessRandomnessURN;
    String hatC_iURN;
    for (BaseRepresentation vertex : vertexIterator) {
      witnessRandomnessURN =
          "possessionprover.witnesses.randomness.vertex.tildem_i_" + vertex.getBaseIndex();
      tildem_i = (BigInteger) proofStore.retrieve(witnessRandomnessURN);

      commitmentVerifier =
          (CommitmentVerifier) VerifierFactory.newVerifier(VerifierType.CommitmentVerifier);

      GroupElement hatCommitment =
          commitmentVerifier.computeWitness(
              vertex, proofStore, extendedPublicKey, keyGenParameters);

      commitmentVerifierList.add(commitmentVerifier);
      hatC_iURN = "commitmentverifier.commitments.hatC_i_" + vertex.getBaseIndex();

      try {
        proofStore.store(hatC_iURN, hatCommitment);
      } catch (Exception e) {
        gslog.log(Level.SEVERE, e.getMessage());
      }
    }
  }

  public void populateStore(ProofSignature p_3) throws ProofStoreException {
    String ZURN = "verifier.Z";
    String APrimeURN = "verifier.APrime";
    String cURN = "verifier.c";
    //    String C_iURN = "verifier.C_i";
    String hatvURN = "verifier.hatv";

    verifierStore.store(cURN, P_3.get("proofsignature.P_3.c"));
    verifierStore.store(ZURN, extendedPublicKey.getPublicKey().getBaseZ());
    verifierStore.store(APrimeURN, P_3.get("proofsignature.P_3.APrime"));
    /** TODO check storage of C_i */
    //    verifierStore.store(C_iURN, P_3.get("proofsignature.P_3.C_i"));

    for (Entry<URN, GSCommitment> commitmentEntry : C_i.entrySet()) {
      URN commitmentKey = commitmentEntry.getKey();
      GSCommitment commitment = commitmentEntry.getValue();
      proofStore.save(commitmentKey, commitment);
    }
  }

  public void close() {
    verifier.close();
  }
}
