package eu.prismacloud.primitives.zkpgs.signer;

import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedKeyPair;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import java.math.BigInteger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultUndirectedGraph;
import org.jgrapht.io.ImportException;

/** Signer */
public class GSSigner { // implements ISigner {
  private static final String SIGNER_GRAPH_FILE = "signer-infra.graphml";
  private GSRecipient recipient;
  private BigInteger nonce;
  private final ExtendedKeyPair extendedKeyPair;
  private KeyGenParameters keyGenParameters;
  /** The Signer graph. */
  private GSGraph<GSVertex, GSEdge> signerGraph;

  private IMessageGateway messageGateway;
  private static GSMessage receiveMessage;

  public GSSigner(final ExtendedKeyPair extendedKeyPair, KeyGenParameters keyGenParameters) {
    this.extendedKeyPair = extendedKeyPair;
    this.keyGenParameters = keyGenParameters;
    this.messageGateway = new MessageGatewayProxy();
  }

  /**
   * Gets signer graph.
   *
   * @return the signer graph
   */
  public GSGraph<GSVertex, GSEdge> getSignerGraph() {
    return signerGraph;
  }

  /** encodeGraph */
  public void encodeGraph() {}

  /**
   * Init graph gs graph.
   *
   * @return the gs graph
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
   * @return the gs message
   */
  public static void sendMessage(GSMessage signerMessageToRecipient, GSRecipient recipient) {
    GSRecipient.receiveMessage(signerMessageToRecipient);
  }

  public BigInteger computeNonce() {
    return CryptoUtilsFacade.computeRandomNumber(keyGenParameters.getL_H());
  }

  public static void receiveMessage(GSMessage recMessageToSigner) {
    GSSigner.receiveMessage = recMessageToSigner;
  }

  public GSMessage getMessage() {
    return receiveMessage;
  }
}
