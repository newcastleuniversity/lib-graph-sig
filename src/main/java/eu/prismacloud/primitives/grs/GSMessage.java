package eu.prismacloud.primitives.grs;

import eu.prismacloud.primitives.grs.commitment.GSCommitment;
import eu.prismacloud.primitives.grs.commitment.ICommitment;
import eu.prismacloud.primitives.grs.signer.GSGraphSignature;
import eu.prismacloud.primitives.grs.signer.GSSigner; /**
 * Created by Ioannis Sfyrakis on 27/07/2017
 */
public class GSMessage implements IMessage {
    public void addCommitment(ICommitment recipientCommitment) {
    }

    public void sendTo(GSSigner signer) {
    }

    public GSMessage receive(GSMessage msg) {
        return null;
    }

    public GSCommitment getCommitment() {
        return null;
    }

    public void addSignature(GSGraphSignature partialGSignature) {
    }

    public GSGraphSignature getSignature() {
        return null;
    }
}
