package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.BaseRepresentation.BASE;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessagePartner;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.IURNGoverner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.store.URN;
import eu.prismacloud.primitives.zkpgs.util.BaseCollection;
import eu.prismacloud.primitives.zkpgs.util.BaseIterator;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class GSRecipient implements IMessagePartner, IURNGoverner {

  private final ExtendedPublicKey extendedPublicKey;
  private final KeyGenParameters keyGenParameters;
  private final BigInteger modN;
  private final GroupElement baseS;
  private final ProofStore<Object> recipientStore;
  private final MessageGatewayProxy messageGateway;
  private BigInteger n_1;
  private GroupElement R_0;
  private BigInteger m_0;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private GSMessage receiveMessage;
  private BaseRepresentation baseRepresentationR_0;
  private GroupElement R_0com;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private static final String SERVER = "server";

  public GSRecipient(ExtendedPublicKey extendedPublicKey) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = extendedPublicKey.getKeyGenParameters();
    this.modN = extendedPublicKey.getPublicKey().getModN();
    this.baseS = extendedPublicKey.getPublicKey().getBaseS();
    this.recipientStore = new ProofStore<Object>();
    this.messageGateway = new MessageGatewayProxy(SERVER);
  }
  
  public void init() throws IOException {
	  this.messageGateway.init();
  }

  public BigInteger generatevPrime() {
    return CryptoUtilsFacade.computeRandomNumberMinusPlus(
        this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());
  }

  public GSCommitment commit(BaseCollection encodedBases, BigInteger rnd) {
    GSCommitment gsCommitment =  GSCommitment.createCommitment(encodedBases, rnd, extendedPublicKey);

    return gsCommitment;
  }

  public GSGraph<GSVertex, GSEdge> getRecipientGraph() {
    return this.recipientGraph;
  }

  public void sendMessage(GSMessage recMessageToSigner) throws IOException {
    messageGateway.send(recMessageToSigner);
  }

  public GSMessage receiveMessage() throws IOException {
    return messageGateway.receive();
  }

  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph) {
    this.recipientGraph = recipientGraph;
  }

  public BigInteger generateN_2() {
    return CryptoUtilsFacade.computeRandomNumber(this.keyGenParameters.getL_H());
  }

  public void close() throws IOException {
    messageGateway.close();
  }
}
