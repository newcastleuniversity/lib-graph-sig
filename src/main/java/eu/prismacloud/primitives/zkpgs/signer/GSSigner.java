package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.GSMessage;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPrivateKey;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.keys.IGSKeyPair;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import java.math.BigInteger;
import org.jgrapht.graph.DefaultEdge;

/** Signer */
public class GSSigner implements ISigner {

  /** The Signer graph. */
  GSGraph signerGraph = new GSGraph();

  /**
   * Algorithm 11 - topocert-doc Key generation algorithm for the graph signature scheme and
   * commitment scheme
   *
   * @param gs_params graph signature scheme parameters
   * @return public key pk, secret key sk, signature sigma
   */
  public IGSKeyPair keyGen(KeyGenParameters gs_params) {
    //        generateRandomSafePrime p= 2p' + 1

    //        generateRandomSafePrime q= 2q' + 1
    return null;
  }

  public GSCommitment commit(GSGraph gsGraph, BigInteger rnd) {
    return null;
  }

  public GSGraphSignature hiddenSign(
      GSCommitment cmt,
      GSVertex signerVertex,
      GSVertex recipientVertex,
      ExtendedPublicKey extendedPublicKey,
      GSGraph gsGraph1,
      ExtendedPrivateKey extendedPrivateKey) {
    return null;
  }

  /**
   * Gets signer graph.
   *
   * @return the signer graph
   */
  public GSGraph getSignerGraph() {
    return signerGraph;
  }

  /** Create graph. */
  public void createGraph() {

    GSVertex v1 = new GSVertex();
    v1.setLabel("vertex_1");
    GSVertex v2 = new GSVertex();
    v2.setLabel("vertex_2");

    signerGraph.addVertex(v1);
    signerGraph.addVertex(v2);

    DefaultEdge edge = signerGraph.addEdge(v1, v2);

    GSVertex signerConnectingVertex = new GSVertex();
    signerConnectingVertex.setLabel("conn_vertex_3");

    signerGraph.addVertex(signerConnectingVertex);
  }

  /**
   * Init graph gs graph.
   *
   * @return the gs graph
   */
  public GSGraph initGraph() {
    return new GSGraph();
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

  public void setGraph(GSGraph signerGraph) {
    // TODO Auto-generated method stub

  }
}
