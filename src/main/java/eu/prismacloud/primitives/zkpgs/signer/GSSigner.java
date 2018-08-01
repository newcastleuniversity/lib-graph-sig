package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;

/** Signer */
public class GSSigner { // implements ISigner {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private GSRecipient recipient;
  private BigInteger nonce;
  private final ExtendedKeyPair extendedKeyPair;
  private final KeyGenParameters keyGenParameters;
  /** The Signer graph. */
  private GSGraph<GSVertex, GSEdge> signerGraph;

  private static final String CLIENT = "client";
  private final MessageGatewayProxy messageGateway;
  private GSMessage receiveMessage;

  /**
   * Instantiates a new signer.
   *
   * @param extendedKeyPair the extended key pair
   * @param keyGenParameters the key gen parameters
   */
  public GSSigner(final ExtendedKeyPair extendedKeyPair, KeyGenParameters keyGenParameters) {
    this.extendedKeyPair = extendedKeyPair;
    this.keyGenParameters = keyGenParameters;
    this.messageGateway = new MessageGatewayProxy(CLIENT);
  }

  /**
   * Init graph gs graph.
   *
   * @return the gs graph
   * @throws ImportException the import exception
   */
  public GSGraph<GSVertex, GSEdge> initGraph() throws ImportException {
    Graph<GSVertex, GSEdge> g = new DefaultUndirectedGraph<GSVertex, GSEdge>(GSEdge.class);

    GSGraph<GSVertex, GSEdge> graph = new GSGraph<GSVertex, GSEdge>(g);

    g = graph.createGraph(SIGNER_GRAPH_FILE);
    GSGraph<GSVertex, GSEdge> gsGraph = new GSGraph<>(g);
    return gsGraph;
  }

  /**
   * Send message gs message.
   *
   * @param signerMessageToRecipient the signer message to recipient
   */
  public void sendMessage(GSMessage signerMessageToRecipient) {
    messageGateway.send(signerMessageToRecipient);
  }

  /**
   * Compute a uniformly random number nonce with length l_H.
   *
   * @return random number
   */
  public BigInteger computeNonce() {
    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
  }

  /**
   * Receive message gs message.
   *
   * @return the gs message
   */
  public GSMessage receiveMessage() {
    return messageGateway.receive();
  }

  /** Close. */
  public void close() {
    messageGateway.close();
  }
}
