package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;

public interface IMessage {
  void addCommitment(ICommitment recipientCommitment);

  ICommitment getCommitment();
}
