package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.commitment.ICommitment;


public interface IMessage {
    void addCommitment(ICommitment recipientCommitment);

    ICommitment getCommitment();
}
