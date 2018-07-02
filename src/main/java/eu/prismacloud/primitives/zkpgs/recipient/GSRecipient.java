package eu.prismacloud.primitives.zkpgs.recipient;

import eu.prismacloud.primitives.zkpgs.BaseRepresentation;
import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;
import eu.prismacloud.primitives.zkpgs.store.ProofStore;
import eu.prismacloud.primitives.zkpgs.util.CryptoUtilsFacade;
import eu.prismacloud.primitives.zkpgs.util.URN;
import eu.prismacloud.primitives.zkpgs.util.crypto.GroupElement;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class GSRecipient { // implements IRecipient {

  private final ExtendedPublicKey extendedPublicKey;
  private final KeyGenParameters keyGenParameters;
  private final BigInteger modN;
  private final GroupElement baseS;
  private final ProofStore<Object> recipientStore;
  private BigInteger n_1;
  private BigInteger vPrime;
  private GroupElement R_0;
  private BigInteger m_0;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private BigInteger n_2;
  private static GSMessage receiveMessage;
  private BaseRepresentation baseRepresentationR_0;

  public GSRecipient(ExtendedPublicKey extendedPublicKey, KeyGenParameters keyGenParameters) {
    this.extendedPublicKey = extendedPublicKey;
    this.keyGenParameters = keyGenParameters;
    modN = extendedPublicKey.getPublicKey().getModN();
    baseS = extendedPublicKey.getPublicKey().getBaseS();
    recipientStore = new ProofStore<Object>();
  }

  public BigInteger generatevPrime() {
    this.vPrime =
        CryptoUtilsFacade.computeRandomNumberMinusPlus(
            this.keyGenParameters.getL_n() + this.keyGenParameters.getL_statzk());

    return this.vPrime;
  }

  public GSCommitment commit(Map<URN, BaseRepresentation> encodedBases, BigInteger rnd) {
    baseRepresentationR_0 = encodedBases.get(URN.createZkpgsURN("bases.R_0"));
    R_0 = baseRepresentationR_0.getBase();
    m_0 = baseRepresentationR_0.getExponent();

    BigInteger commitment = R_0.modPow(m_0, modN).multiply(baseS.modPow(rnd, modN)).getValue();
    Map<URN, GroupElement> bases = new HashMap<>();
    bases.put(URN.createZkpgsURN("recipient.bases.R_0"), this.R_0);
    Map<URN, BigInteger> messages = new HashMap<>();
    messages.put(URN.createZkpgsURN("recipient.bases.m_0"), this.m_0);

    GSCommitment gsCommitment = new GSCommitment(bases, messages, rnd, this.baseS, this.modN);

    return gsCommitment;
  }

  public GSGraph<GSVertex, GSEdge> getRecipientGraph() {
    return this.recipientGraph;
  }

  public static void sendMessage(GSMessage recMessageToSigner, GSSigner signer) {
    GSSigner.receiveMessage(recMessageToSigner);
  }

  //  @Override
  public void setGraph(GSGraph<GSVertex, GSEdge> recipientGraph) {
    this.recipientGraph = recipientGraph;
  }

  public BigInteger generateN_2() {
    this.n_2 = CryptoUtilsFacade.computeRandomNumber(this.keyGenParameters.getL_H());

    return this.n_2;
  }

  public static void receiveMessage(GSMessage signerMessageToRecipient) {
    GSRecipient.receiveMessage = signerMessageToRecipient;
  }

  public GSMessage getMessage() {

    return receiveMessage;
  }
}
