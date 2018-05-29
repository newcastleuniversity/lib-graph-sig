package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.signer.GSGraphSignature;
import eu.prismacloud.primitives.zkpgs.signer.GSSigner;

public class GSMessage implements IMessage {
  public void addCommitment(ICommitment recipientCommitment) {}

  public void sendTo(GSSigner signer) {}

  public GSMessage receive(GSMessage msg) {
    return null;
  }

  public GSCommitment getCommitment() {
    return null;
  }

  public void addSignature(GSGraphSignature partialGSignature) {}

  public GSGraphSignature getSignature() {
    return null;
  }
}
