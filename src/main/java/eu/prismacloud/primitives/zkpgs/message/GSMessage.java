package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class GSMessage implements Serializable {

  private static final long serialVersionUID = -8931520272759188134L;

  /** TODO finish gsmessage class to use a proxy */
  Map<URN, Object> messageElements = new HashMap<>();

  private GSSignature graphSignature;
  private GSCommitment gsCommitment;

  public GSMessage() {}

  public GSMessage(Map<URN, Object> messageElements) {
    this.messageElements = messageElements;
  }


  public Map<URN, Object> getMessageElements() {
    return this.messageElements;
  }

  public void addCommitment(GSCommitment recipientCommitment) {}

  public GSMessage receive(GSMessage msg) {
    return msg;
  }

  public GSCommitment getCommitment() {
    return gsCommitment;
  }

  public void addSignature(GSSignature partialGSignature) {
    this.graphSignature = partialGSignature;
  }

  public GSSignature getSignature() {
    return graphSignature;
  }
}
