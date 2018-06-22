package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.GraphRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.orchestrator.IssuingOrchestrator;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.NumberConstants;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import eu.prismacloud.primitives.zkpgs.verifier.CommitmentVerifier;
import java.math.BigInteger;
import java.util.Map;
import org.jgrapht.io.ImportException;

/** Signer */
public class GSSigner { // implements ISigner {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private GSRecipient recipient;
  private BigInteger nonce;
  private final IssuingOrchestrator issuingOrchestrator;
  private KeyGenParameters keyGenParameters;

  /** The Signer graph. */
  private GSGraph<GSVertex, GSEdge> signerGraph;

  private BigInteger rnd;
  private Map<URN, Object> messageElements;
  private BigInteger e;
  private BigInteger vbar;
  private BigInteger vPrimePrime;
  private Map<URN, Object> proofSignatureElements;
  private BigInteger hatvPrime;
  private BigInteger hatm_0;
  private BigInteger c;
  private Map<String, BigInteger> vertexResponses;
  private Map<String, BigInteger> edgeResponses;
  private ICommitment U;
  private Map<URN, BaseRepresentation> encodedEdges;
  private Map<URN, BaseRepresentation> encodedVertices;
  private GSSignature gsSignature;

  public GSSigner(
      final IssuingOrchestrator issuingOrchestrator, final KeyGenParameters keyGenParameters) {
    this.issuingOrchestrator = issuingOrchestrator;
    this.keyGenParameters = keyGenParameters;
  }

  /**
   * Gets signer graph.
   *
   * @return the signer graph
   */
  public GSGraph<GSVertex, GSEdge> getSignerGraph() {
    return signerGraph;
  }

  /** Create graph. */
  public void createGraph() {}

  /**
   * Init graph gs graph.
   *
   * @return the gs graph
   */
  public GSGraph<GSVertex, GSEdge> initGraph() throws ImportException {
    return (GSGraph<GSVertex, GSEdge>) signerGraph.createGraph(SIGNER_GRAPH_FILE);
  }

  /**
   * Send message gs message.
   *
   * @param signerMessageToRecipient the signer message to recipient
   * @return the gs message
   */
  public GSMessage sendMessage(GSMessage signerMessageToRecipient) {
    return null;
  }

  public void receiveMessage(GSMessage recMessageToSigner) {

    messageElements = recMessageToSigner.getMessageElements();
  }

  public CommitmentVerifier createCommitmentVerifier(
      ProofSignature P_1,
      ICommitment U,
      BigInteger n_1,
      GroupElement baseS,
      GroupElement baseR_0,
      GroupElement baseZ,
      BigInteger modN,
      Map<URN, BaseRepresentation> bases
    ) {

    proofSignatureElements = P_1.getProofSignatureElements();
    hatvPrime =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatvPrime"));
    // TODO check if hatm_0 is needed inside the proofsignature
    hatm_0 =
        (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_0"));
    this.U = U;
    c = (BigInteger) proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.c"));
    vertexResponses =
        (Map<String, BigInteger>)
            proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_i"));

    edgeResponses =
        (Map<String, BigInteger>)
            proofSignatureElements.get(URN.createZkpgsURN("proofsignature.P_1.hatm_i_j"));

    CommitmentVerifier commitmentVerifier =
        new CommitmentVerifier(
            hatvPrime,
            hatm_0,
            U,
            c,
            baseS,
            baseZ,
            baseR_0,
            n_1,
            modN,
            bases,
            vertexResponses,
            edgeResponses,
            keyGenParameters);

    return commitmentVerifier;
  }

  public void createPartialSignature(ExtendedKeyPair extendedPublicKey) {
    gsSignature =
        new GSSignature(
            extendedPublicKey,
            U,
            GraphRepresentation.getEncodedBases(),
            keyGenParameters);
  }

  public void computeRandomness() {
    int eBitLength = (keyGenParameters.getL_e() - 1) + (keyGenParameters.getL_prime_e() - 1);
    e = CryptoUtilsFacade.computePrimeWithLength(keyGenParameters.getL_e() - 1, eBitLength);

    vbar = CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_v() - 1);
  }

  public void computevPrimePrime() {
    vPrimePrime = NumberConstants.TWO.getValue().pow(keyGenParameters.getL_v() - 1).add(vbar);
  }

  public void store() {
    /** TODO store Q, vPrimePrime and context */
  }

  public void createCorrectnessProver() {}

  public BigInteger computeNonce() {
    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
  }
}
