package eu.prismacloud.primitives.zkpgs;

import eu.prismacloud.primitives.zkpgs.commitment.GSCommitment;
import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;

public interface IMessage {
  void addCommitment(ICommitment recipientCommitment);

  GSCommitment getCommitment();
}
