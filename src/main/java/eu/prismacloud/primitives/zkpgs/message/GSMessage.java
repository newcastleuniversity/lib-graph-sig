package eu.prismacloud.primitives.zkpgs.message;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.signature.GSSignature;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.util.HashMap;
import java.util.Map;

public class GSMessage<T> implements IMessage {

  /** TODO finish gsmessage class to use a proxy */
  Map<URN, Object> messageElements = new HashMap<>();
  private GSSignature graphSignature;
  private GSCommitment gsCommitment;

  public GSMessage() {}

  public GSMessage(Map<URN, Object> messageElements) {
    this.messageElements = messageElements;
  }

  public GSMessage(Object messageElement) {
    //    this.messageElements.put(, )
  }

  public void sendTo(Object receiver, T message) {
    /** TODO add implementation for sendTo method */
  }

  public Map<URN, Object> getMessageElements() {
    return this.messageElements;
  }

  public void addCommitment(GSCommitment recipientCommitment) {}

  public GSMessage receive(GSMessage msg) {
    return msg;
  }

  @Override
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
