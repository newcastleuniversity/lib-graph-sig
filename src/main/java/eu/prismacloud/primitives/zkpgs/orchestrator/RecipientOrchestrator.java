package eu.prismacloud.primitives.zkpgs.orchestrator;

import eu.prismacloud.primitives.zkpgs.commitment.ICommitment;
import eu.prismacloud.primitives.zkpgs.graph.GSEdge;
import eu.prismacloud.primitives.zkpgs.graph.GSGraph;
import eu.prismacloud.primitives.zkpgs.graph.GSVertex;
import eu.prismacloud.primitives.zkpgs.keys.ExtendedPublicKey;
import eu.prismacloud.primitives.zkpgs.message.GSMessage;
import eu.prismacloud.primitives.zkpgs.message.IMessageGateway;
import eu.prismacloud.primitives.zkpgs.message.MessageGatewayProxy;
import eu.prismacloud.primitives.zkpgs.parameters.KeyGenParameters;
import eu.prismacloud.primitives.zkpgs.prover.IssuingCommitmentProver;
import eu.prismacloud.primitives.zkpgs.prover.ProofSignature;
import eu.prismacloud.primitives.zkpgs.recipient.GSRecipient;
import eu.prismacloud.primitives.zkpgs.util.URN;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

/** Recipient orchestrator */
public class RecipientOrchestrator {

  private final ExtendedPublicKey pk;
  private KeyGenParameters keyGenParameters;
  private GSRecipient recipient;
  private BigInteger n_1;
  private BigInteger n_2;
  private GSGraph<GSVertex, GSEdge> recipientGraph; // = new GSGraph();
  private ProofSignature P_1;
  private ICommitment U;
  IMessageGateway messageGateway;

  public RecipientOrchestrator(ExtendedPublicKey pk, KeyGenParameters keyGenParameters) {
    this.pk = pk;
    this.keyGenParameters = keyGenParameters;
  }

  public ExtendedPublicKey getExtendedPublicKey() {
    return this.pk;
  }

  public void round1() {
    // TODO needs to receive message n_1
	  
    BigInteger vPrime = recipient.generatevPrime();
    U = recipient.commit(recipientGraph, vPrime);
     
    /** TODO generalize commit prover */
    /** TODO add commitment factory */
    // TODO needs to get access to commitment secrets (recipientGraph)
    IssuingCommitmentProver commitmentProver = recipient.createCommitmentProver(U, pk); // TODO Needs access to secrets

    P_1 = commitmentProver.createProofSignature(); // TODO Needs to sign n_1

    n_2 = recipient.generateN_2();

    Map<URN, Object> messageElements = new HashMap<>();
    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.U"), U);

    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.P_1"), P_1);

    messageElements.put(URN.createURN(URN.getZkpgsNameSpaceIdentifier(), "recipient.n_2"), n_2);

    // recipient.sendMessage(new GSMessage(messageElements), signer);

    /** TODO store context and randomness vPrime */
  }

  
public void round3() {}
}
