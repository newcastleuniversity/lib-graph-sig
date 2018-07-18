package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.GSLoggerConfiguration;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

public class GSRecipient { // implements IRecipient {

  private ExtendedPublicKey extendedPublicKey;
  private final KeyGenParameters keyGenParameters;
  private final BigInteger modN;
  private final GroupElement baseS;
  private final ProofStore<Object> recipientStore;
  private MessageGatewayProxy messageGateway;
  private BigInteger n_1;
  //  private BigInteger vPrime;
  private GroupElement R_0;
  private BigInteger m_0;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private static GSMessage receiveMessage;
  private BaseRepresentation baseRepresentationR_0;
  private GroupElement R_0com;
  private Logger gslog = GSLoggerConfiguration.getGSlog();
  private static final String SERVER = "server";

  public GSRecipient(ExtendedPublicKey extendedPublicKey, KeyGenParameters keyGenParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    modN = extendedPublicKey.getPublicKey().getModN();
    baseS = extendedPublicKey.getPublicKey().getBaseS();
    recipientStore = new ProofStore<Object>();
    this.messageGateway = new MessageGatewayProxy(SERVER);
  }

  public void bootStrap() {
    GSMessage msg = messageGateway.receive();
    Map<URN, Object> elements = msg.getMessageElements();
    extendedPublicKey =
        (ExtendedPublicKey) elements.get(URN.createZkpgsURN("signer.ExtendedPublicKey"));
  }

  public BigInteger generatevPrime() {
    return CryptoUtilsFacade.computeRandomNumberMinusPlus(
        this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());
  }

  public GSCommitment commit(Map<URN, BaseRepresentation> encodedBases, BigInteger rnd) {
    baseRepresentationR_0 = encodedBases.get(URN.createZkpgsURN("bases.R_0"));
    R_0 = baseRepresentationR_0.getBase();
    m_0 =  baseRepresentationR_0.getExponent();
    R_0com = R_0.modPow(m_0);
    GroupElement baseScom = baseS.modPow(rnd);

    gslog.info("recipient R_0:  " + R_0);
    gslog.info("recipient m_0: " + m_0);

    //    BigInteger commitment = R_0.modPow(m_0, modN).multiply(baseS.modPow(rnd,
    // modN)).getValue();

    GroupElement commitment = R_0com.multiply(baseScom);

    gslog.info("recipient commitment value:  " + commitment);

    Map<URN, GroupElement> bases = new HashMap<>();
    bases.put(URN.createZkpgsURN("recipient.bases.R_0"), R_0);
    Map<URN, BigInteger> messages = new HashMap<>();
    messages.put(URN.createZkpgsURN("recipient.exponent.m_0"), m_0);

    GSCommitment gsCommitment = new GSCommitment(bases, messages, rnd, this.baseS, this.modN);
    gsCommitment.setCommitmentValue(commitment);

    //    gsCommitment.commit();
    gslog.info("recipient commit: " + gsCommitment.getCommitmentValue());
    return gsCommitment;
  }

  public GSGraph<GSVertex, GSEdge> getRecipientGraph() {
    return this.recipientGraph;
  }

  public void sendMessage(GSMessage recMessageToSigner) {
    messageGateway.send(recMessageToSigner);
  }

  public GSMessage receiveMessage() {
    return messageGateway.receive();
  }

  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph) {
    this.recipientGraph = recipientGraph;
  }

  public BigInteger generateN_2() {
    return CryptoUtilsFacade.computeRandomNumber(this.keyGenParameters.getL_H());
  }
}
