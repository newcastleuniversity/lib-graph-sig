package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.commitment.ICommitment;

/**
 * Created by Ioannis Sfyrakis on 27/07/2017
 */
public interface IMessage {
    void addCommitment(ICommitment recipientCommitment);

    ICommitment getCommitment();
}
