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
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.parameters.GraphEncodingParameters;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.CommitmentProver.STAGE;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory;
import eu.prismacloud.primitives.zkpgs.prover.ProverFactory.ProverType;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CorrectnessVerifier;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory;
import eu.prismacloud.primitives.zkpgs.verifier.VerifierFactory.VerifierType;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;

/** Recipient orchestrator */
public class RecipientOrchestrator {

  private static final String RECIPIENT_GRAPH_FILE = "recipient.graphml";
  private final ExtendedPublicKey extendedPublicKey;
  private final ProofStore<Object> proofStore;
  private final BigInteger modN;
  private final GroupElement baseS;
  private final GroupElement R_0;
  private final GroupElement baseZ;
  private final KeyGenParameters keyGenParameters;
  private final GraphEncodingParameters graphEncodingParameters;
  private GSRecipient recipient;
  private BigInteger n_1;
  private BigInteger n_2;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private ProofSignature P_1;
  private GSCommitment U;
  private IMessageGateway messageGateway;
  private GSSigner signer;
  private Map<URN, BaseRepresentation> encodedBases;
  private BigInteger recipientMSK;
  private GSCommitment tildeU;
  private List<String> challengeList;
  private BigInteger cChallenge;
  private Map<URN, BigInteger> responses;
  private Map<URN, BaseRepresentation> correctnessEncodedBases;
  private BigInteger A;
  private BigInteger e;
  private BigInteger vPrimePrime;
  private ProofSignature P_2;
  private BigInteger v;
  private BigInteger vPrime;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private List<String> contextList;

  public RecipientOrchestrator(
      final ExtendedPublicKey extendedPublicKey,
      final KeyGenParameters keyGenParameters,
      final GraphEncodingParameters graphEncodingParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    this.graphEncodingParameters = graphEncodingParameters;
    this.proofStore = new ProofStore<Object>();
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.baseZ = extendedPublicKey.getPublicKey().getBaseZ();
    this.R_0 = extendedPublicKey.getPublicKey().getBaseR_0();
  }

  public void round1() {
    generateRecipientMSK();

    try {
      createGraphRepresentation();
    } catch (ImportException e) {
      e.printStackTrace();
    }

    encodeR_0();

    // TODO needs to receive message n_1
    GSMessage msg = recipient.receiveMessage();
    BigInteger n_1 = (BigInteger) msg.getMessageElements().get(URN.createZkpgsURN("nonces.n_1"));

    vPrime = recipient.generatevPrime();

    U = recipient.commit(encodedBases, vPrime);

    /** TODO generalize commit prover */
    /** TODO add commitment factory */
    // TODO needs to get access to commitment secrets (recipientGraph)
    CommitmentProver commitmentProver =
        (CommitmentProver) ProverFactory.newProver(ProverType.CommitmentProver);

    commitmentProver.preChallengePhase(
        encodedBases, proofStore, extendedPublicKey, keyGenParameters, STAGE.ISSUING);

    tildeU = commitmentProver.getWitness();

    try {
      computeChallenge();
    } catch (NoSuchAlgorithmException ns) {
      ns.getMessage();
    }

    responses = commitmentProver.postChallengePhase(cChallenge);

    //        recipient.createCommitmentProver(U, extendedPublicKey); // TODO Needs access to
    // secrets

    P_1 = createProofSignature(); // TODO Needs to sign n_1

    n_2 = recipient.generateN_2();

    Map<URN, Object> messageElements = new HashMap<>();
    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.U"), U);

    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.P_1"), P_1);

    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.n_2"), n_2);

    recipient.sendMessage(new GSMessage(messageElements), signer);

    /** TODO store context and randomness vPrime */
  }

  public void computeChallenge() throws NoSuchAlgorithmException {
    challengeList = populateChallengeList();
    cChallenge = CryptoUtilsFacade.computeHash(challengeList, keyGenParameters.getL_H());
  }

  private List<String> populateChallengeList() {
    /** TODO add context to list of elements in challenge */

    contextList = GSContext.computeChallengeContext(extendedPublicKey,keyGenParameters ,graphEncodingParameters );

    challengeList.add(String.valueOf(modN));
    challengeList.add(String.valueOf(baseS.getValue()));
    challengeList.add(String.valueOf(baseZ.getValue()));
    //    challengeList.add(R);
    challengeList.add(String.valueOf(R_0.getValue()));

    for (BaseRepresentation baseRepresentation : encodedBases.values()) {
      challengeList.add(String.valueOf(baseRepresentation.getBase().getValue()));
    }

    challengeList.add(String.valueOf(U.getCommitmentValue()));
    challengeList.add(String.valueOf(tildeU.getCommitmentValue()));
    challengeList.add(String.valueOf(n_1));

    return challengeList;
  }

  private void encodeR_0() {
    BaseRepresentation base = encodedBases.get(URN.createZkpgsURN("bases.R_0"));
    BaseRepresentation baseR_0 =
        new BaseRepresentation(
            base.getBase(), recipientMSK, base.getBaseIndex(), base.getBaseType());
    encodedBases.replace(URN.createZkpgsURN("bases.R_0"), baseR_0);
  }

  private void generateRecipientMSK() {
    recipientMSK = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_m());
  }

  private void createGraphRepresentation() throws ImportException {
    Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GSGraph<GSVertex, GSEdge> graph = new GSGraph<GSVertex, GSEdge>(g);

    g = graph.createGraph(RECIPIENT_GRAPH_FILE);

    graph.encodeGraph(g, this.graphEncodingParameters);
    GraphMLProvider.createImporter();
    GSGraph<GSVertex, GSEdge> gsGraph = new GSGraph<>(g);
    GraphRepresentation.encode(gsGraph, graphEncodingParameters, extendedPublicKey);
    encodedBases = GraphRepresentation.getEncodedBases();
  }

  /**
   * Create proof signature proof signature.
   *
   * @return the proof signature
   */
  public ProofSignature createProofSignature() {
    Map<URN, Object> proofSignatureElements = new HashMap<>();
    BigInteger hatvPrime;
    BigInteger hatm_0;
    String hatvPrimeURN = "issuing.commitmentprover.responses.hatvPrime";
    String hatm_0URN = "issuing.commitmentprover.responses.hatm_0";

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.c"), cChallenge);
    hatvPrime = (BigInteger) proofStore.retrieve(hatvPrimeURN);
    hatm_0 = (BigInteger) proofStore.retrieve(hatm_0URN);

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"), hatvPrime);
    // TODO check if hatm_0 is needed inside the proofsignature
    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.hatm_0"), hatm_0);

    proofSignatureElements.put(URN.createZkpgsURN("proofsignature.P_1.responses"), responses);

    return new ProofSignature(proofSignatureElements);
  }

  public void round3() throws VerificationException {

    GSMessage correctnessMsg = recipient.receiveMessage();
    ProofSignature P_2 = extractMessageElements(correctnessMsg);
    
    v = vPrimePrime.add(vPrime);

    CorrectnessVerifier correctnessVerifier = (CorrectnessVerifier) VerifierFactory.newVerifier(VerifierType.CorrectnessVerifier);

    correctnessVerifier.preChallengePhase(e,
          v,
           P_2,
           A,
          extendedPublicKey,
          n_2,
          encodedBases,
          keyGenParameters,
        graphEncodingParameters);

    try {
      correctnessVerifier.computeChallenge();
    } catch (NoSuchAlgorithmException ns) {
      ns.getMessage();
    }

    if (!correctnessVerifier.verifyChallenge()) {
      throw new VerificationException("challenge cannot be verified");
    }

    try {
      proofStore.store("recipient.graphsignature.A" ,  A);
      proofStore.store("recipient.graphsignature.e", e);
      proofStore.store("recipient.graphsignature.v", v);
      
    } catch (Exception e1) {
      e1.printStackTrace();
    }

    for (Map.Entry<URN, BaseRepresentation> base : encodedBases.entrySet()) {
      try {
        proofStore.save(base.getKey(),base.getValue() );
      } catch (Exception e1) {
        e1.printStackTrace();
      }
    }
  }

  private ProofSignature extractMessageElements(GSMessage correctnessMsg) {
    Map<URN, Object> correctnessMessageElements = correctnessMsg.getMessageElements();

    A = (BigInteger) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.A"));
    e = (BigInteger) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.e"));
    vPrimePrime =
        (BigInteger)
            correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.vPrimePrime"));
    P_2 = (ProofSignature) correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.P_2"));
    correctnessEncodedBases =
        (Map<URN, BaseRepresentation>)
            correctnessMessageElements.get(URN.createZkpgsURN("proofsignature.encoding"));

    return P_2;
  }
}
