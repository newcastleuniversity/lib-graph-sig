package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.GraphMLProvider;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
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
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.util.crypto.QRElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier.STAGE;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory.VerifierType;
import java.io.File;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.GraphImporter;

/** Signing orchestrator */
public class SignerOrchestrator {

  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
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
  private GSCommitment U;
  private IMessageGateway messageGateway;
  private Map<URN, Object> messageElements;
  private GSRecipient recipient;
  private GSCommitment commitmentU;
  private BigInteger cChallenge;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private Map<URN, BigInteger> responses;
  private GroupElement hatU;
  private List<String> challengeList;
  private BigInteger hatc;
  private GSSignature gsSignature;
  private BigInteger e;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private GroupElement Q;
  private QRElement R_i;
  private QRElement R_i_j;
  private BigInteger d;
  private GroupElement A;
  private Map<URN, BaseRepresentation> encodedBases;
  private GSGraph<GSVertex, GSEdge> gsGraph;
  private BigInteger order;
  private BigInteger hatd;
  private BigInteger cPrime;
  private Map<URN, Object> p2ProofSignatureElements;
  private ProofSignature P_2;
  private Map<URN, Object> correctnessMessageElements;
  private List<String> contextList;
  private Graph<GSVertex, GSEdge> graph;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private GroupElement R_0;
  private BigInteger pPrime;
  private BigInteger qPrime;
  private GroupElement Sv;
  private GroupElement R_0multi;
  private GroupElement Sv1;

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
    //    gsGraph = signer.initGraph();

    File file = GraphMLProvider.getGraphMLFile(SIGNER_GRAPH_FILE);

    graph = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);
    GraphImporter<GSVertex, GSEdge> importer = GraphMLProvider.createImporter();

    importer.importGraph(graph, file);

    gsGraph = new GSGraph<>(graph);

    graph = gsGraph.createGraph(SIGNER_GRAPH_FILE);

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

    p2ProofSignatureElements = new HashMap<URN, Object>();

    p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.hatd"), hatd);
    p2ProofSignatureElements.put(URN.createZkpgsURN("P_2.cPrime"), cPrime);

    P_2 = new ProofSignature(p2ProofSignatureElements);

    correctnessMessageElements = new HashMap<URN, Object>();

//    verifySignature();

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

  private void verifySignature() throws Exception {
    BigInteger vPrime = U.getRandomness();
    gslog.info("signer vPrime: " + vPrime);

    BigInteger v = vPrimePrime.add(vPrime);
    R_0 = U.getBasesR().get(URN.createZkpgsURN("recipient.bases.R_0"));

    gslog.info("recipient.R_0: " + R_0);

    BigInteger m_0 = U.getExponents().get(URN.createZkpgsURN("recipient.exponent.m_0"));

    gslog.info("recipient.m_0: " + m_0);

    GroupElement R_0multi = R_0.modPow(m_0);
    GroupElement Ae = A.modPow(e);
    GroupElement baseSmulti = baseS.modPow(v);

    GroupElement hatZ = Ae.multiply(R_0multi).multiply(baseSmulti);
    //        R_0multi
    //            .multiply(A.modPow(e, modN).multiply(baseS.modPow(v, modN).getValue()))
    //            .getValue();

    gslog.info("signer hatZ: " + hatZ);
    BigInteger modZ = baseZ.getValue().mod(modN);
    gslog.info("signer base Z:" + modZ);

    if (!baseZ.equals(hatZ)) throw new Exception("wrong signature A");
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

    challengeList = new ArrayList<String>();
    contextList =
        GSContext.computeChallengeContext(
            extendedKeyPair.getExtendedPublicKey(), keyGenParameters, graphEncodingParameters);

    //    challengeList.addAll(contextList);

    /** TODO add context to list of elements in challenge */
    challengeList.add(String.valueOf(modN));
    challengeList.add(String.valueOf(baseS.getValue()));
    challengeList.add(String.valueOf(baseZ.getValue()));
    //    challengeList.add(R_0);

    //    for (BaseRepresentation baseRepresentation : baseRepresentationMap.values()) {
    //      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
    //    }
    String uCommitmentURN = "recipient.U";
    U = (GSCommitment) proofStore.retrieve(uCommitmentURN);
    gslog.info("commitment U: " + U.getCommitmentValue());
    gslog.info("hatU: " + hatU);
    challengeList.add(String.valueOf(U.getCommitmentValue()));
    //    challengeList.add(String.valueOf(hatU));
    challengeList.add(String.valueOf(n_1));

    return challengeList;
  }

  private ProofSignature extractMessageElements(GSMessage msg) throws Exception {
    Map<URN, Object> messageElements = msg.getMessageElements();

    commitmentU = (GSCommitment) messageElements.get(URN.createZkpgsURN("recipient.U"));

    //    proofStore.store("recipient.U", commitmentU );

    ProofSignature P_1 = (ProofSignature) messageElements.get(URN.createZkpgsURN("recipient.P_1"));
    Map<URN, Object> proofSignatureElements = P_1.getProofSignatureElements();

    cChallenge =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.c"));
    //    proofStore.store("proofsignature.P_1.c", cChallenge );

    hatvPrime =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"));

    //    proofStore.store("proofsignature.P_1.hatvPrime", hatvPrime);
    hatm_0 =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_0"));

    //    proofStore.store("proofsignature.P_1.hatm_0", hatm_0);

    responses =
        (Map<URN, BigInteger>)
            proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.responses"));

    //    proofStore.store("proofsignature.P_1.responses", responses);

    n_2 = (BigInteger) messageElements.get(URN.createZkpgsURN("recipient.n_2"));

    //    proofStore.store("recipient.n_2", n_2);

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
    proofStore.store("recipient.U", commitmentU);
    proofStore.store("recipient.n_2", n_2);
  }

  public void createPartialSignature(ExtendedPublicKey extendedPublicKey) {

    computeQ();
    computeA();

    gsSignature = new GSSignature(extendedPublicKey, U, this.encodedBases, keyGenParameters);
  }

  public void computeRandomness() {

    //    BigInteger min = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_e() - 1);
    //       BigInteger max =
    //           min.add(NumberConstants.TWO.getValue().pow(keyGenParameters.getL_prime_e() - 1));

    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);

    vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
  }

  public void computevPrimePrime() {
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
  }

  public void store() throws Exception {
    proofStore.store("issuing.signer.A", A);
    proofStore.store("issuing.signer.Q", Q);
    proofStore.store("issuing.signer.d", d);
    proofStore.store("issuing.signer.vPrimePrime", vPrimePrime);
    proofStore.store("issuing.signer.context", contextList);
  }

  public GroupElement computeQ() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);
    vbar = CryptoUtilsFacade.computeRandomNumberMinusPlus(keyGenParameters.getL_v() - 1);
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);

    //    for (BaseRepresentation encodedBase : encodedBases.values()) {
    //      if (encodedBase.getExponent() != null) {
    //        if (encodedBase.getBaseType() == BASE.VERTEX) {
    //          if (R_i == null) {
    //            R_i = encodedBase.getBase().modPow(encodedBase.getExponent(), modN);
    //          } else {
    //            R_i = R_i.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(), modN));
    //          }
    //
    //        } else if (encodedBase.getBaseType() == BASE.EDGE) {
    //
    //          if (R_i_j == null) {
    //
    //            R_i_j = encodedBase.getBase().modPow(encodedBase.getExponent(), modN);
    //
    //          } else {
    //            R_i_j = R_i_j.multiply(encodedBase.getBase().modPow(encodedBase.getExponent(),
    // modN));
    //          }
    //        }
    //      }
    //    }

    //    BigInteger invertible = U.getCommitmentValue().multiply(baseS.modPow(vPrimePrime,
    // modN).multiply(R_i).multiply(R_i_j).mod(modN));

    R_0 = extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseR_0();
    BigInteger m_0 = U.getExponents().get(URN.createZkpgsURN("recipient.exponent.m_0"));


    Sv = baseS.modPow(vPrimePrime);
    R_0multi = R_0.modPow(m_0);
    Sv1 = Sv.multiply(R_0multi);

    Q = baseZ.multiply(Sv1.modInverse());

//    QRElement R_0multi =
//        extendedKeyPair.getExtendedPublicKey().getPublicKey().getBaseR_0().modPow(m_0, modN);
//    BigInteger Uvalue = U.getCommitmentValue();
//
//    //    BigInteger numerator = pk.getGeneratorS().modPow(v, n).multiply(R).multiply(U).mod(n);
//    BigInteger invertible =
//        baseS.modPow(vPrimePrime, modN).multiply(R_0multi).multiply(Uvalue).mod(modN);

    //    BigInteger invertible =
    //        U.getCommitmentValue().multiply(baseS.modPow(vPrimePrime, modN).getValue());

    gslog.info("signer U commitment: " + U.getCommitmentValue());

//    Q = baseZ.multiply(invertible.modInverse(modN)).mod(modN);
    gslog.info("signer Q: " + Q);
    gslog.info("signer e: " + e);
    gslog.info("signer Z: " + baseZ);
    gslog.info("signer S: " + baseS);

    return Q;
  }

  public GroupElement computeA() {
    pPrime = extendedKeyPair.getExtendedPrivateKey().getPrivateKey().getpPrime();
    qPrime = extendedKeyPair.getExtendedPrivateKey().getPrivateKey().getqPrime();

    d = e.modInverse(pPrime.multiply(qPrime));

    // TODO Remove logging of values that can break security (secret key or modInverse mod order;

    A = Q.modPow(d);
    gslog.info("signer A: " + A);
    return A;
  }
}
