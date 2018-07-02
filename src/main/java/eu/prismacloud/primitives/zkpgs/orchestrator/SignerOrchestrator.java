package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.context.GSContext;
import eu.prismacloud.primitives.zkpgs.exception.VerificationException;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CorrectnessProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory.ProverType;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory.VerifierType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Signing orchestrator */
public class SignerOrchestrator {

  private final ExtendedKeyPair extendedKeyPair;
  private final ProofStore<Object> proofStore;
  private final GroupElement baseS;
  private final BigInteger modN;
  private final GroupElement baseZ;
  private final Map<URN, BaseRepresentation> baseRepresentationMap;
  private KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private GSSigner signer;
  private BigInteger n_1;
  private BigInteger n_2;
  private ProofSignature P_1;
  private ICommitment U;
  private IMessageGateway messageGateway;
  private Map<URN, Object> messageElements;
  private GSRecipient recipient;
  private GSCommitment gsCommitment;
  private BigInteger cChallenge;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private Map<URN, BigInteger> responses;
  private BigInteger hatU;
  private List<String> challengeList;
  private BigInteger hatc;
  private GSSignature gsSignature;
  private BigInteger e;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private BigInteger Q;
  private QRElement R_i;
  private QRElement R_i_j;
  private BigInteger d;
  private BigInteger A;
  private Map<URN, BaseRepresentation> encodedBases;
  private GSGraph<GSVertex, GSEdge> gsGraph;
  private BigInteger order;
  private BigInteger hatd;
  private BigInteger cPrime;
  private Map<URN, Object> p2ProofSignatureElements;
  private ProofSignature P_2;
  private Map<URN, Object> correctnessMessageElements;
  private List<String> contextList;

  public SignerOrchestrator(
      ExtendedKeyPair extendedKeyPair,
      KeyGenParameters keyGenParameters,
      GraphEncodingParameters graphEncodingParameters) {
    this.extendedKeyPair = extendedKeyPair;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.proofStore = new ProofStore<Object>();
    this.baseS = extendedKeyPair.getPublicKey().getBaseS();
    this.baseZ = extendedKeyPair.getPublicKey().getBaseZ();
    this.modN = extendedKeyPair.getPublicKey().getModN();
    this.baseRepresentationMap = extendedKeyPair.getExtendedPublicKey().getBases();
    this.signer = new GSSigner(extendedKeyPair, keyGenParameters);
    this.recipient = new GSRecipient(extendedKeyPair.getExtendedPublicKey(), keyGenParameters);
  }

  public void round0() {
    n_1 = signer.computeNonce();
    messageElements = new HashMap<URN, Object>();
    messageElements.put(URN.createZkpgsURN("nonces.n_1"), n_1);
    signer.sendMessage(new GSMessage(messageElements), recipient);

    /** TODO send message to recipient for the n_1 */
    /** TODO signer send n_1 to recipient */
  }

  public void round2() throws Exception {
    gsGraph = signer.initGraph();

    GraphRepresentation.encode(
        gsGraph, graphEncodingParameters, extendedKeyPair.getExtendedPublicKey());

    this.encodedBases = GraphRepresentation.getEncodedBases();

    // TODO needs to receive input message (U, P_1, n_2)
    // TODO value store needs to be populated (note this is on a different computer...)

    GSMessage msg = signer.getMessage();
    ProofSignature P_1 = extractMessageElements(msg);

    CommitmentVerifier commitmentVerifier =
        (CommitmentVerifier) VerifierFactory.newVerifier(VerifierType.CommitmentVerifier);

    hatU =
        commitmentVerifier.computeWitness(
            cChallenge,
            responses,
            proofStore,
            extendedKeyPair.getExtendedPublicKey(),
            keyGenParameters,
            STAGE.ISSUING);

    computeChallenge();

    if (!verifyChallenge()) {
      throw new VerificationException("challenge verification failed");
    }

    computeRandomness();
    computevPrimePrime();
    createPartialSignature(extendedKeyPair.getExtendedPublicKey());
    store();

    order =
        extendedKeyPair
            .getPrivateKey()
            .getpPrime()
            .multiply(extendedKeyPair.getPrivateKey().getqPrime());

    CorrectnessProver correctnessProver =
        (CorrectnessProver) ProverFactory.newProver(ProverType.CorectnessProver);
    correctnessProver.preChallengePhase(
        gsSignature,
        order,
        n_2,
        proofStore,
        extendedKeyPair.getExtendedPublicKey(),
        keyGenParameters);

    cPrime = correctnessProver.computeChallenge();

    hatd = correctnessProver.postChallengePhase();

    p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.hatd"), hatd);
    P_2 = new ProofSignature(p2ProofSignatureElements);

    correctnessMessageElements.put(URN.createZkpgsURN("proofsignature.A"), A);
    correctnessMessageElements.put(URN.createZkpgsURN("proofsignature.e"), e);
    correctnessMessageElements.put(URN.createZkpgsURN("proofsignature.vPrimePrime"), vPrimePrime);
    correctnessMessageElements.put(URN.createZkpgsURN("proofsignature.P_2"), P_2);
    correctnessMessageElements.put(
        URN.createZkpgsURN("proofsignature.encoding"), this.encodedBases);

    GSMessage correctnessMsg = new GSMessage(correctnessMessageElements);

    signer.sendMessage(correctnessMsg, recipient);

    //    v = vPrimePrime.add(vPrime);
  }
  /** Compute challenge. */
  public void computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    hatc = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  public Boolean verifyChallenge() {
    return hatc.equals(cChallenge);
  }

  private List<String> populateChallengeList() {

    contextList =
        GSContext.computeChallengeContext(
            extendedKeyPair.getExtendedPublicKey(), keyGenParameters, graphEncodingParameters);

    challengeList.addAll(contextList);

    /** TODO add context to list of elements in challenge */
    challengeList.add(String.valueOf(modN));
    challengeList.add(String.valueOf(baseS.getValue()));
    challengeList.add(String.valueOf(baseZ.getValue()));
    //     challengeList.add(R_0);

    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
    }

    challengeList.add(String.valueOf(U.getCommitment()));
    challengeList.add(String.valueOf(hatU));
    challengeList.add(String.valueOf(n_1));

    return challengeList;
  }

  private ProofSignature extractMessageElements(GSMessage msg) throws Exception {
    Map<URN, Object> messageElements = msg.getMessageElements();

    gsCommitment = (GSCommitment) messageElements.get(URN.createZkpgsURN("recipient.U"));

    ProofSignature P_1 = (ProofSignature) messageElements.get(URN.createZkpgsURN("recipient.P_1"));
    Map<URN, Object> proofSignatureElements = P_1.getProofSignatureElements();

    cChallenge =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.c"));

    hatvPrime =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"));
    hatm_0 =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_0"));

    responses =
        (Map<URN, BigInteger>)
            proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses"));

    n_2 = (BigInteger) messageElements.get(URN.createZkpgsURN("recipient.n_2"));

    storeMessageElements(P_1);

    return P_1;
  }

  private void storeMessageElements(ProofSignature P_1) throws Exception {
    for (Map.Entry<URN, BigInteger> response : responses.entrySet()) {
      proofStore.save(response.getKey(), response.getValue());
    }

    proofStore.store("proofsignature.P_1.c", cChallenge);
    proofStore.store("proofsignature.P_1.hatvPrime", hatvPrime);
    proofStore.store("proofsignature.P_1.hatm_0", hatm_0);
    proofStore.store("recipient.P_1", P_1);
    proofStore.store("recipient.U", gsCommitment);
    proofStore.store("recipient.n_2", n_2);
  }

  public void createPartialSignature(ExtendedPublicKey extendedPublicKey) {

    computeQ();
    computeA();

    gsSignature = new GSSignature(extendedPublicKey, U, this.encodedBases, keyGenParameters);
  }

  public void computeRandomness() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);

    vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
  }

  public void computevPrimePrime() {
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
  }

  public void store() throws Exception {
    proofStore.store("issuing.signer.Q", Q);
    proofStore.store("issuing.signer.vPrimePrime", vPrimePrime);
    proofStore.store("issuing.signer.context", contextList);
  }

  public BigInteger computeQ() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);
    vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);

    for (BaseRepresentation encodedBase : encodedBases.values()) {
      if (encodedBase.getBaseType() == BASE.VERTEX) {
        R_i = R_i.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN));
      } else if (encodedBase.getBaseType() == BASE.EDGE) {
        R_i_j = R_i_j.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN));
      }
    }

    BigInteger invertible = baseS.modPow(vPrimePrime, modN).multiply(R_i).multiply(R_i_j).mod(modN);
    Q = baseZ.multiply(invertible.modInverse(modN)).mod(modN);

    return Q;
  }

  public BigInteger computeA() {
    d = e.modInverse(modN);

    // TODO Remove logging of values that can break security (secret key or modInverse mod order;

    A = Q.modPow(d, modN);
    return A;
  }
}
