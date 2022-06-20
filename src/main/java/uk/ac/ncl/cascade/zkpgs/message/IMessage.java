package uk.ac.ncl.cascade.zkpgs.message;

import uk.ac.ncl.cascade.zkpgs.commitment.GSCommitment;

public interface IMessage {
  void addCommitment(GSCommitment recipientCommitment);

  GSCommitment getCommitment();
}
